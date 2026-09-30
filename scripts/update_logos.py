import os
from PIL import Image

src_dir = r"C:\Users\User\.gemini\antigravity-ide\brain\35fb1d7f-f9c0-470f-a897-f4b5dbe7b205"
dest_dir = r"d:\DNS\static\img"

brand_logo_src = os.path.join(src_dir, "dnswatch_brand_logo_1790744053137.jpg")
app_icon_src = os.path.join(src_dir, "dnswatch_app_icon_1790744071472.jpg")

# 1. Process App Icon
if os.path.exists(app_icon_src):
    img_icon = Image.open(app_icon_src)
    # Save as logo_icon.png (high-res PNG)
    img_icon.save(os.path.join(dest_dir, "logo_icon.png"), "PNG", quality=95)
    print("Saved logo_icon.png")

# 2. Process Brand Logo (Horizontal)
if os.path.exists(brand_logo_src):
    img_brand = Image.open(brand_logo_src)
    # Save full version
    img_brand.save(os.path.join(dest_dir, "logo.png"), "PNG", quality=95)
    img_brand.save(os.path.join(dest_dir, "dnswatch_logo.png"), "PNG", quality=95)
    
    # Crop tightly around the shield and text
    # The image is 1792x1024 or 1920x1080 (16:9)
    w, h = img_brand.size
    # Left: ~10% to ~90%, Top: ~20% to ~80%
    crop_box = (int(w * 0.12), int(h * 0.22), int(w * 0.88), int(h * 0.78))
    img_tight = img_brand.crop(crop_box)
    img_tight.save(os.path.join(dest_dir, "logo_tight.png"), "PNG", quality=95)
    img_tight.save(os.path.join(dest_dir, "logo_cropped.png"), "PNG", quality=95)
    print(f"Saved logo_tight.png with dimensions {img_tight.size}")

print("Logo assets successfully updated in", dest_dir)
