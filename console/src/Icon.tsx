import { createElement } from "react";
import { ICONS, type IconName, type Weight } from "./icons.generated";

export type { IconName, Weight };

/**
 * A Phosphor icon (the set the Argus HUD uses) drawn as inline SVG: no font, no image request, colour from
 * `currentColor`. Decorative by default (`aria-hidden`); pass `label` when the icon alone carries meaning.
 */
export function Icon({ name, weight = "regular", size = 18, className, label }: {
  name: IconName;
  weight?: Weight;
  size?: number;
  className?: string;
  label?: string;
}) {
  const shapes = ICONS[name][weight];
  return (
    <svg
      viewBox="0 0 256 256"
      width={size}
      height={size}
      fill="currentColor"
      className={className ? `ic ${className}` : "ic"}
      focusable="false"
      aria-hidden={label ? undefined : true}
      role={label ? "img" : undefined}
      aria-label={label}
    >
      {shapes.map(([tag, attrs], i) => createElement(tag, { key: i, ...attrs }))}
    </svg>
  );
}
