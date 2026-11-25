from pathlib import Path
from typing import Sequence

from PIL import Image

ROOT = Path(__file__).resolve().parents[2]
SOURCE_ICON_PATH = ROOT / 'logo.png'
TARGET_PNG_PATH = ROOT / 'desktop-app' / 'frontend' / 'public' / 'brand' / 'appicon.png'
TARGET_ICO_PATH = ROOT / 'desktop-app' / 'frontend' / 'public' / 'brand' / 'appicon.ico'
ICO_SIZES: tuple[tuple[int, int], ...] = ((16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256))


def ensure_parent_directories(paths: Sequence[Path]) -> None:
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)


def build_resized_icon(image: Image.Image, size: tuple[int, int]) -> Image.Image:
    resized: Image.Image = image.copy()
    resized.thumbnail(size, Image.Resampling.LANCZOS)

    canvas: Image.Image = Image.new('RGBA', size, (0, 0, 0, 0))
    offset_x: int = (size[0] - resized.width) // 2
    offset_y: int = (size[1] - resized.height) // 2
    canvas.paste(resized, (offset_x, offset_y), resized)
    return canvas


def write_icon_assets() -> None:
    if not SOURCE_ICON_PATH.is_file():
        raise FileNotFoundError(f'源图标不存在: path={SOURCE_ICON_PATH}')

    ensure_parent_directories((TARGET_PNG_PATH, TARGET_ICO_PATH))

    with Image.open(SOURCE_ICON_PATH) as source_image:
        base_image: Image.Image = source_image.convert('RGBA')
        png_image: Image.Image = build_resized_icon(base_image, (512, 512))
        png_image.save(TARGET_PNG_PATH, format='PNG')

        icon_frames: list[Image.Image] = [build_resized_icon(base_image, size) for size in ICO_SIZES]
        largest_frame: Image.Image = icon_frames[-1]
        largest_frame.save(
            TARGET_ICO_PATH,
            format='ICO',
            sizes=ICO_SIZES,
            append_images=icon_frames[:-1],
        )

    print(f'已同步图标: source={SOURCE_ICON_PATH} png={TARGET_PNG_PATH} ico={TARGET_ICO_PATH}')


if __name__ == '__main__':
    write_icon_assets()
