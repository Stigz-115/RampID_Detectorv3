#!/bin/bash
# Streamlit Cloud setup script
# Installs Playwright browser binaries after package installation
# Streamlit Cloud runs this automatically if named setup.sh

echo "Installing Playwright Chromium browser..."

# System deps are already installed via packages.txt, so just install the browser binary
playwright install chromium

if [ $? -eq 0 ]; then
    echo "Playwright Chromium installed successfully."
else
    echo "WARNING: Playwright browser install failed. App will fall back to requests mode."
fi
