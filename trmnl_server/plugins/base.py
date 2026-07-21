"""Plugin contract: something that periodically produces a pair of frames.

Trimmed relative to upstream. `ChartPlugin` and `PhotographicPlugin` were
dropped along with the plugins that subclassed them (weather, charts, hn,
xkcd, bing, random_image) — nothing in this fork draws grayscale charts,
and keeping ~470 lines of monotone-Hermite curve fitting alive for no
caller is a maintenance liability. `PluginOutput` and `PluginBase` are
unchanged, so the scheduler and rotation state see exactly the upstream
interface.

Note for anything rendering 1-bit output: `save_assets()` routes the image
through `prepare_image()` (`convert('L')`) and then `save_display_assets()`
with the default 4-level grayscale quantiser, which dithers. That destroys
mode-"1" FreeType rasterisation. Screens that are already 1-bit must write
their own files instead — see `plugins/garmin.py`.
"""

from abc import ABC, abstractmethod
import logging
from dataclasses import dataclass
from typing import Optional, Tuple

from PIL import Image, ImageOps, ImageEnhance, ImageFont

from ..utils import save_display_assets, load_font as utils_load_font

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PluginOutput:
    """Paths to the generated monochrome BMP and grayscale PNG assets."""

    monochrome_path: str
    grayscale_path: str


class PluginBase(ABC):
    """Abstract base class for image-producing plugins with optional adjustments."""

    BASENAME: str = 'plugin'
    OUTPUT_SUBDIR: Optional[str] = None
    SET_PRIMARY: bool = False
    AUTO_REGISTER: bool = True
    REFRESH_INTERVAL: Optional[int] = None
    REGISTRY_ORDER: int = 100

    def __init__(self):
        self.name = self.__class__.__name__

    def get_display_name(self) -> str:
        display_attr = getattr(self, 'DISPLAY_NAME', None)
        return str(display_attr) if display_attr else self.name

    @abstractmethod
    async def run(self, **kwargs) -> Optional[PluginOutput]:
        """Execute the plugin logic asynchronously."""
        raise NotImplementedError

    def get_adjustment_settings(self) -> Tuple[bool, float, float]:
        """Return (apply_contrast, gamma_value, contrast_cutoff)."""
        return (False, 1.0, 0.0)

    def get_content_ttl(self) -> int:
        """Number of seconds this plugin's output remains fresh."""
        return 900

    def apply_adjustments(self, image: Image.Image) -> Image.Image:
        """Apply optional contrast and gamma adjustments according to plugin settings."""
        apply_contrast, gamma_value, contrast_cutoff = self.get_adjustment_settings()
        adjusted = image

        if apply_contrast:
            adjusted = ImageOps.autocontrast(adjusted, cutoff=contrast_cutoff)

        if gamma_value and gamma_value != 1.0:
            inv_gamma = 1.0 / gamma_value
            adjusted = adjusted.point(
                lambda value: max(0, min(255, int(round((value / 255.0) ** inv_gamma * 255))))
            )

        return adjusted

    @staticmethod
    def lift_black_point(image: Image.Image, offset: int = 16) -> Image.Image:
        """Raise the black point to recover detail in deep shadows."""
        offset = max(0, min(offset, 64))
        lut = [min(255, value + offset) for value in range(256)]
        return image.point(lut)

    @staticmethod
    def boost_shadows(image: Image.Image, pivot: int = 180, shadow_gamma: float = 0.7) -> Image.Image:
        """Brighten tonal values below the pivot using a gamma curve."""
        pivot = max(1, min(pivot, 254))
        pivot_norm = pivot / 255.0
        lut = []
        for value in range(256):
            normalized = value / 255.0
            if normalized < pivot_norm:
                ratio = normalized / pivot_norm
                remapped = (ratio ** shadow_gamma) * pivot_norm
            else:
                remapped = normalized
            lut.append(int(round(remapped * 255)))
        return image.point(lut)

    def apply_eink_grading(
        self,
        image: Image.Image,
        *,
        shadow_pivot: int = 180,
        shadow_gamma: float = 0.65,
        brightness: float = 1.1,
        contrast_cutoff: float = 0.05
    ) -> Image.Image:
        """Apply a shadow lift, brightness tweak, and autocontrast pass."""
        lifted = self.boost_shadows(image, pivot=shadow_pivot, shadow_gamma=shadow_gamma)
        brightened = ImageEnhance.Brightness(lifted).enhance(brightness)
        return ImageOps.autocontrast(brightened, cutoff=contrast_cutoff)

    def prepare_image(self, image: Image.Image) -> Image.Image:
        """Convert plugin output to grayscale and apply the configured adjustments."""
        grayscale = image.convert('L') if image.mode != 'L' else image
        return self.apply_adjustments(grayscale)

    def save_assets(
        self,
        image: Image.Image,
        output_dir: str,
        basename: str,
        dither_mode: Optional[str] = None
    ) -> PluginOutput:
        """Apply uniform processing and persist BMP/PNG outputs for the plugin."""
        prepared = self.prepare_image(image)
        bmp_path, png_path = save_display_assets(
            prepared,
            output_dir,
            basename,
            dither_mode=dither_mode
        )
        return PluginOutput(monochrome_path=bmp_path, grayscale_path=png_path)

    @staticmethod
    def load_font(size: int, fallback_paths: Optional[Tuple[str, ...]] = None) -> ImageFont.ImageFont:
        """Attempt to load a font from several candidate paths, falling back gracefully."""
        return utils_load_font(size, fallback_paths)
