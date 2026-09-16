export type Workshop = {
  title: string;
  category: string;
};

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => {
    switch (character) {
      case "&":
        return "&amp;";
      case "<":
        return "&lt;";
      case ">":
        return "&gt;";
      case '"':
        return "&quot;";
      default:
        return "&#39;";
    }
  });
}

export function render(items: Workshop[], category = "all"): string {
  const visibleItems =
    category === "all"
      ? items
      : items.filter((item) => item.category === category);

  return (
    "<ul>" +
    visibleItems
      .map((item) => "<li>" + escapeHtml(item.title) + "</li>")
      .join("") +
    "</ul>"
  );
}
