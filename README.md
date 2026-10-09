# macOS signing executor

Fixed recipes for authenticated signing requests. Inputs are verified as data; source build scripts are never executed here. Credentials are issued only to the pinned workflow and removed when its job ends.
