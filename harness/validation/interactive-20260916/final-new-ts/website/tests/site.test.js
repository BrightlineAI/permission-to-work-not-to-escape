import assert from "node:assert/strict";
import test from "node:test";

import { render } from "../dist/site.js";

test("filters workshops by category", () => {
  const workshops = [
    { title: "TypeScript Basics", category: "coding" },
    { title: "Watercolour Landscapes", category: "art" },
    { title: "Advanced TypeScript", category: "coding" },
  ];

  assert.equal(
    render(workshops, "coding"),
    "<ul><li>TypeScript Basics</li><li>Advanced TypeScript</li></ul>",
  );
});

test("escapes workshop titles before inserting them into HTML", () => {
  const workshops = [
    { title: '<script>alert("x")</script> & \'friends\'', category: "security" },
  ];

  assert.equal(
    render(workshops),
    "<ul><li>&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt; &amp; &#39;friends&#39;</li></ul>",
  );
});

test("renders an empty list for empty input", () => {
  assert.equal(render([]), "<ul></ul>");
});
