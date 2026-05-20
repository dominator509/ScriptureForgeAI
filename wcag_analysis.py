import re

def calculate_relative_luminance(hex_color):
    hex_color = hex_color.lstrip('#')
    if len(hex_color) == 3:
        hex_color = ''.join([c*2 for c in hex_color])

    rgb = tuple(int(hex_color[i:i+2], 16) / 255.0 for i in (0, 2, 4))

    def adjust(val):
        return val / 12.92 if val <= 0.03928 else ((val + 0.055) / 1.055) ** 2.4

    r, g, b = map(adjust, rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b

def calculate_contrast_ratio(hex1, hex2):
    lum1 = calculate_relative_luminance(hex1)
    lum2 = calculate_relative_luminance(hex2)

    l1 = max(lum1, lum2)
    l2 = min(lum1, lum2)

    return (l1 + 0.05) / (l2 + 0.05)

# Known color pairs found in UI
colors = [
    ("#1D4ED8", "#FFFFFF", "Primary Button (Web)"),
    ("#10B981", "#FFFFFF", "Generate Button (Web)"),
    ("#E5E7EB", "#9CA3AF", "Input Placeholder (Web)"),
    ("#FFFFFF", "#4B5563", "Study Plan Container (Web)"),
    ("#F9FAFB", "#111827", "Scripture Reader Background vs Text (Mobile)"),
    ("#F9FAFB", "#6B7280", "Scripture Reader Background vs Secondary Text (Mobile)"),
    ("#2563EB", "#FFFFFF", "Commentary Button (Mobile)")
]

print("Color Contrast Analysis:")
for bg, fg, name in colors:
    ratio = calculate_contrast_ratio(bg, fg)
    status = "PASS" if ratio >= 4.5 else "FAIL"
    print(f"- {name}: {bg} vs {fg} -> Ratio: {ratio:.2f}:1 [{status}]")
