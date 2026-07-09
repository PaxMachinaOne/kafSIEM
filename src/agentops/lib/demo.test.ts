import { afterEach, expect, test } from "vitest";
import { alertsURL, currentDemoMode, demoShellMode, incidentsURL } from "@/agentops/lib/demo";

afterEach(() => {
  window.history.replaceState({}, "", "/");
});

test("routes osint demo to bundled fixtures and OSINT shell", () => {
  window.history.replaceState({}, "", "/?demo=osint");
  expect(currentDemoMode()).toBe("osint");
  expect(demoShellMode()).toBe("OSINT");
  expect(alertsURL()).toContain("demo/alerts.json");
  expect(incidentsURL()).toContain("demo/incidents.json");
});

test("routes fusion demo to hybrid shell with bundled OSINT fixtures", () => {
  window.history.replaceState({}, "", "/?demo=fusion");
  expect(currentDemoMode()).toBe("fusion");
  expect(demoShellMode()).toBe("HYBRID");
  expect(incidentsURL()).toContain("demo/incidents.json");
});