import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import "@fontsource-variable/inter/opsz.css";

import { App } from "./App";
import "./goralTokens.css";
import "./styles.css";
import "./notesScripts.css";
import "./knownHosts.css";
import "./goralSkin.css";
import "./goralContrast.css";
import "./mainWorkspaceSkin.css";
import "./mainWorkspaceRebuild.css";
import "./mainWorkspaceFrame.css";
import "./goralTypography.css";
import "./aiPanel.css";

const root = document.getElementById("root");

if (!root) {
  throw new Error("Goral root element is missing");
}

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
