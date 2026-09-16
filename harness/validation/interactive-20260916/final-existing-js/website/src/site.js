function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function render(items, category = "all") {
  const visibleItems = category === "all"
    ? items
    : items.filter(item => item.category === category);

  return "<ul>" + visibleItems
    .map(item => "<li>" + escapeHtml(item.title) + "</li>")
    .join("") + "</ul>";
}
