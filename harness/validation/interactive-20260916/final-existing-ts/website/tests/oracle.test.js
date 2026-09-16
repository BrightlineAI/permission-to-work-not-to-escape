import test from "node:test";
import assert from "node:assert/strict";
import {render} from "../dist/site.js";
test("category filter", () => { const page = render([{title:"Safety",category:"ai"},{title:"Music",category:"arts"}], "ai"); assert.ok(page.includes("Safety"));assert.ok(!page.includes("Music")); });
test("HTML escaping", () => assert.ok(render([{title:"<script>",category:"ai"}]).includes("&lt;script&gt;")));
test("empty list", () => assert.equal(render([]), "<ul></ul>"));
