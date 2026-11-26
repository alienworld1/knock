import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";

export default defineConfig({
  site: process.env.SITE_URL || "https://alienworld1.github.io",
  base: process.env.BASE_PATH ?? "/knock",
  integrations: [
    starlight({
      title: "knock",
      titleDelimiter: "|",
      description:
        "A front door for private Linux servers. Temporary, verified SSH and service tunnels with enforced expiration.",
      favicon: "/favicon.svg",
      social: [
        {
          icon: "github",
          label: "GitHub",
          href: "https://github.com/alienworld1/knock",
        },
      ],
      customCss: [
        "@fontsource/ibm-plex-sans/400.css",
        "@fontsource/ibm-plex-sans/500.css",
        "@fontsource/ibm-plex-sans/600.css",
        "@fontsource/ibm-plex-mono/400.css",
        "@fontsource/ibm-plex-mono/500.css",
        "./src/styles/theme.css",
      ],
      expressiveCode: {
        styleOverrides: {
          borderRadius: "6px",
          borderWidth: "1px",
          borderColor: "var(--k-border)",
          codeFontFamily: "var(--k-font-mono)",
          codeFontSize: "0.84375rem",
          codeLineHeight: "1.55",
          frames: {
            shadowColor: "transparent",
          },
        },
      },
      components: {
        SiteTitle: "./src/components/SiteTitle.astro",
        ThemeProvider: "./src/components/ThemeProvider.astro",
        ThemeSelect: "./src/components/ThemeSelect.astro",
      },
      sidebar: [
        {
          label: "Start here",
          items: [
            { label: "Overview", slug: "getting-started/overview" },
            { label: "Installation", slug: "getting-started/installation" },
            { label: "Quickstart", slug: "getting-started/quickstart" },
          ],
        },
        {
          label: "Core concepts",
          items: [
            { label: "Session lifecycle", slug: "concepts/lifecycle" },
            { label: "Approval Doors", slug: "concepts/approval-doors" },
            { label: "Metered Doors", slug: "concepts/metered-doors" },
            { label: "Operator console", slug: "concepts/operator-console" },
            { label: "Audit history", slug: "concepts/audit-history" },
          ],
        },
        {
          label: "CLI reference",
          items: [
            { label: "knock CLI", slug: "cli/knock" },
            { label: "knockd daemon", slug: "cli/knockd" },
          ],
        },
        {
          label: "Operations",
          items: [
            { label: "Host setup", slug: "operations/host-setup" },
            { label: "Mailbox service", slug: "operations/mailbox" },
            { label: "Linux verification lab", slug: "operations/linux-lab" },
          ],
        },
        {
          label: "Architecture and security",
          items: [
            { label: "System architecture", slug: "security/architecture" },
            { label: "QoreChain integration", slug: "security/qorechain" },
            { label: "Threat model and limits", slug: "security/threat-model" },
          ],
        },
      ],
    }),
  ],
});
