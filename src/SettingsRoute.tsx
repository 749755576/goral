import { SETTINGS_ADAPTER } from "./settingsApi";
import { SettingsWorkspace } from "./SettingsWorkspace";
import { hideSettingsWindow } from "./settingsWindowApi";

export function SettingsRoute() {
  return (
    <SettingsWorkspace
      adapter={SETTINGS_ADAPTER}
      onClose={() => {
        void hideSettingsWindow();
      }}
    />
  );
}
