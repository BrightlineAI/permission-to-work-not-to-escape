export interface WorkshopItem {
  title: string;
  category: string;
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function render(
  items: readonly WorkshopItem[],
  category = "all",
): string {
  const visibleItems =
    category === "all"
      ? items
      : items.filter((item) => item.category === category);

  return `<ul>${visibleItems
    .map((item) => `<li>${escapeHtml(item.title)}</li>`)
    .join("")}</ul>`;
}
