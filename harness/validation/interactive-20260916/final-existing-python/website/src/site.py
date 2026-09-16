import html


def render(items, category="all"):
    """Render workshop titles, optionally filtering them by category."""
    visible_items = (
        items
        if category == "all"
        else (item for item in items if item.get("category") == category)
    )
    return "<ul>" + "".join(
        "<li>" + html.escape(str(item.get("title", ""))) + "</li>"
        for item in visible_items
    ) + "</ul>"
