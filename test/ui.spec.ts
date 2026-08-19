import { describe, expect, it } from "vitest";
import { renderDeployPage } from "../src/ui";

describe("PrizePicks management UI", () => {
	it("renders the approved brand shell and accessibility safeguards", () => {
		const html = renderDeployPage({
			siteDomain: "internal.example.com",
			deployPath: "/deploy",
		});

		expect(html).toContain('aria-label="PrizePicks Internal Sites"');
		expect(html).toContain(
			"/brand/logos/Pushin%20P%20-%20Secondary%20-%20On%20Dark.svg",
		);
		expect(html).toContain(
			"/brand/fonts/GT-Standard-L-Standard-Regular.ttf",
		);
		expect(html).toContain('font-family: "GT Standard"');
		expect(html).toContain("@media (prefers-reduced-motion: reduce)");
		expect(html).toContain(":focus-visible");
		expect(html).toContain("#8000FF");
		expect(html).toContain("#FBF9FF");
		expect(html).toContain("color-scheme: dark");
		expect(html).toContain("--background: #050614");
		expect(html).toContain("input {\n  background: var(--background);");
		expect(html).toContain(".pill-button {\n  background: var(--background);");
		expect(html).toContain("Maximum file count:");
		expect(html).toContain("Maximum total size:");
		expect(html).toContain('viewBox="0 0 20 20"');
		expect(html).toContain('stroke-width="2"');
		expect(html).not.toContain("fonts.googleapis.com");
		expect(html).not.toContain("oklch(");
		expect(html).not.toContain('font-family: "Inter');
	});
});
