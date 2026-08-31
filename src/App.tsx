import { lazy, Suspense } from "react";

import { TerminalWorkspace } from "./TerminalWorkspace";
import { isSettingsWindowLocation } from "./settingsWindowApi";

const SettingsRoute = lazy(async () => {
  const module = await import("./SettingsRoute");
  return { default: module.SettingsRoute };
});

export function App() {
  if (isSettingsWindowLocation()) {
    return (
      <Suspense fallback={<div className="settings-route-loading">Goral</div>}>
        <SettingsRoute />
      </Suspense>
    );
  }

  return (
    <main className="shell">
      <TerminalWorkspace />
    </main>
  );
}
