"""
DNSWatch Manual DNS Blocking API
----------------------------------
Provides role-gated REST endpoints for:

  ManualBlockRule  (Admin-only create / update / delete)
  BlockRequest     (Analyst submit / Admin approve or reject)

Every add / remove / activate / deactivate automatically:
  1. Calls detection_engine.reload_manual_blocks() so Scapy-captured
     traffic is immediately classified correctly.
  2. Calls dns_sinkhole_service.reload_block_cache() so the live
     sinkhole enforces the change without a restart.
"""
from datetime import datetime

from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user

from database import db
from models import ManualBlockRule, BlockRequest

blocking_bp = Blueprint('blocking', __name__)


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------

def _refresh_engines():
    """Reload both the detection engine and the sinkhole after any rule change."""
    try:
        from services.detection_engine import detection_engine
        detection_engine.reload_manual_blocks()
    except Exception as exc:
        print(f"[blocking] detection_engine reload error: {exc}")
    try:
        from services.dns_sinkhole import dns_sinkhole_service
        dns_sinkhole_service.reload_block_cache()
    except Exception as exc:
        print(f"[blocking] sinkhole cache reload error: {exc}")


# ===================================================================
# Manual Block Rules
# ===================================================================

@blocking_bp.route('/api/blocking/rules', methods=['GET'])
@login_required
def get_block_rules():
    """Return all manual block rules ordered by creation date."""
    rules = ManualBlockRule.query.order_by(ManualBlockRule.created_at.desc()).all()
    return jsonify({'success': True, 'rules': [r.to_dict() for r in rules]})


@blocking_bp.route('/api/blocking/rules', methods=['POST'])
@login_required
def create_block_rule():
    """Create a new manual block rule (Admin only)."""
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Administrator access required.'}), 403

    data = request.get_json() or {}
    domain = (data.get('domain') or '').strip().lower().rstrip('.')
    reason = (data.get('reason') or '').strip()
    source_request_id = data.get('source_request_id')

    if not domain:
        return jsonify({'success': False, 'message': 'Domain is required.'}), 400

    existing = ManualBlockRule.query.filter_by(domain=domain).first()
    if existing:
        if not existing.is_active:
            # Re-activate an existing inactive rule
            existing.is_active = True
            existing.reason = reason or existing.reason
            existing.approved_by = current_user.username
            existing.updated_at = datetime.utcnow()
            db.session.commit()
            _refresh_engines()
            return jsonify({
                'success': True,
                'message': f"Block rule for '{domain}' re-activated.",
                'rule': existing.to_dict()
            })
        return jsonify({'success': False,
                        'message': f"An active block rule for '{domain}' already exists."}), 400

    rule = ManualBlockRule(
        domain=domain,
        reason=reason,
        created_by=current_user.username,
        approved_by=current_user.username,
        source_request_id=source_request_id,
        is_active=True
    )
    db.session.add(rule)
    db.session.commit()
    _refresh_engines()

    return jsonify({
        'success': True,
        'message': f"Domain '{domain}' has been blocked.",
        'rule': rule.to_dict()
    })


@blocking_bp.route('/api/blocking/rules/<int:rule_id>', methods=['PUT'])
@login_required
def update_block_rule(rule_id):
    """Activate / deactivate or update reason of a block rule (Admin only)."""
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Administrator access required.'}), 403

    rule = ManualBlockRule.query.get_or_404(rule_id)
    data = request.get_json() or {}

    if 'is_active' in data:
        rule.is_active = bool(data['is_active'])
    if 'reason' in data:
        rule.reason = (data['reason'] or '').strip()
    rule.updated_at = datetime.utcnow()
    db.session.commit()
    _refresh_engines()

    verb = 'activated' if rule.is_active else 'deactivated'
    return jsonify({
        'success': True,
        'message': f"Block rule for '{rule.domain}' {verb}.",
        'rule': rule.to_dict()
    })


@blocking_bp.route('/api/blocking/rules/<int:rule_id>', methods=['DELETE'])
@login_required
def delete_block_rule(rule_id):
    """Permanently delete a block rule (Admin only)."""
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Administrator access required.'}), 403

    rule = ManualBlockRule.query.get_or_404(rule_id)
    domain = rule.domain
    db.session.delete(rule)
    db.session.commit()
    _refresh_engines()

    return jsonify({'success': True, 'message': f"Block rule for '{domain}' deleted."})


@blocking_bp.route('/api/blocking/summary', methods=['GET'])
@login_required
def get_blocking_summary():
    """Return quick-counts for the sidebar / badge."""
    active_rules    = ManualBlockRule.query.filter_by(is_active=True).count()
    pending_reqs    = BlockRequest.query.filter_by(status='PENDING').count()
    return jsonify({'success': True, 'active_rules': active_rules, 'pending_requests': pending_reqs})


# ===================================================================
# Block Requests
# ===================================================================

@blocking_bp.route('/api/blocking/requests', methods=['GET'])
@login_required
def get_block_requests():
    """Return block requests, optionally filtered by status."""
    status_filter = (request.args.get('status') or '').strip().upper()
    q = BlockRequest.query
    if status_filter and status_filter != 'ALL':
        q = q.filter(BlockRequest.status == status_filter)
    items = q.order_by(BlockRequest.requested_at.desc()).all()
    return jsonify({'success': True, 'requests': [r.to_dict() for r in items]})


@blocking_bp.route('/api/blocking/requests', methods=['POST'])
@login_required
def submit_block_request():
    """Submit a new block request (Security Analyst or Admin)."""
    if not current_user.can_request_block:
        return jsonify({
            'success': False,
            'message': 'Only Security Analysts and Administrators may submit block requests.'
        }), 403

    data   = request.get_json() or {}
    domain = (data.get('domain') or '').strip().lower().rstrip('.')
    reason = (data.get('reason') or '').strip()

    if not domain or not reason:
        return jsonify({'success': False, 'message': 'Domain and reason are required.'}), 400

    # Guard: already actively blocked
    if ManualBlockRule.query.filter_by(domain=domain, is_active=True).first():
        return jsonify({'success': False,
                        'message': f"'{domain}' is already actively blocked."}), 400

    # Guard: duplicate pending request
    existing = BlockRequest.query.filter_by(domain=domain, status='PENDING').first()
    if existing:
        return jsonify({'success': False,
                        'message': f"A pending request for '{domain}' already exists (#{existing.id})."}), 400

    req = BlockRequest(
        domain         = domain,
        client_ip      = (data.get('client_ip') or '').strip(),
        reason         = reason,
        detection_info = (data.get('detection_info') or '').strip(),
        requested_by   = current_user.username,
        requested_at   = datetime.utcnow(),
        status         = 'PENDING'
    )
    db.session.add(req)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': f"Block request for '{domain}' submitted. Awaiting administrator approval.",
        'request': req.to_dict()
    })


@blocking_bp.route('/api/blocking/requests/<int:req_id>/approve', methods=['PUT'])
@login_required
def approve_block_request(req_id):
    """Approve a block request and create / activate the block rule (Admin only)."""
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Administrator access required.'}), 403

    req = BlockRequest.query.get_or_404(req_id)
    if req.status != 'PENDING':
        return jsonify({'success': False, 'message': f"Request is already {req.status}."}), 400

    # Create or re-activate the ManualBlockRule
    rule = ManualBlockRule.query.filter_by(domain=req.domain).first()
    if rule:
        rule.is_active    = True
        rule.approved_by  = current_user.username
        rule.updated_at   = datetime.utcnow()
    else:
        rule = ManualBlockRule(
            domain             = req.domain,
            reason             = req.reason,
            created_by         = req.requested_by,
            approved_by        = current_user.username,
            source_request_id  = req.id,
            is_active          = True
        )
        db.session.add(rule)

    req.status      = 'APPROVED'
    req.reviewed_by = current_user.username
    req.reviewed_at = datetime.utcnow()
    db.session.commit()
    _refresh_engines()

    return jsonify({
        'success': True,
        'message': f"Approved. '{req.domain}' is now blocked.",
        'rule': rule.to_dict()
    })


@blocking_bp.route('/api/blocking/requests/<int:req_id>/reject', methods=['PUT'])
@login_required
def reject_block_request(req_id):
    """Reject a block request with an optional reason (Admin only)."""
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Administrator access required.'}), 403

    req = BlockRequest.query.get_or_404(req_id)
    if req.status != 'PENDING':
        return jsonify({'success': False, 'message': f"Request is already {req.status}."}), 400

    data = request.get_json() or {}
    req.status           = 'REJECTED'
    req.reviewed_by      = current_user.username
    req.reviewed_at      = datetime.utcnow()
    req.rejection_reason = (data.get('rejection_reason') or 'No reason provided.').strip()
    db.session.commit()

    return jsonify({
        'success': True,
        'message': f"Block request for '{req.domain}' rejected.",
        'request': req.to_dict()
    })
