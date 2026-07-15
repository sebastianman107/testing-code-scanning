package main

denied_paths := {
  "/debug/pprof/*"
}

sensitive_paths := {
  "/*",
  "/admin/*",
  "/admin",
  "/admin_console",
  "/internal/*",
  "/heapdump",
  "/debug/*",
  "/metrics",
  "/cleanup/debug/*"
}

deny contains msg if {
  app := input.apps[_]
  bypass := app.bypassHydraRoutes[_]
  operation := bypass.operations[_]
  path := operation.paths[_]
  some denied_path in denied_paths
  contains(path, trim_suffix(denied_path, "/*"))
  msg := {
    "msg": sprintf("App '%s' has denied keyword in bypassHydraRoutes path: '%s'", [app.name, path]),
    "severity": "HIGH",
    "_loc": {"file": data.conftest.file.name, "line": 1}
  }
}

warn contains msg if {
  app := input.apps[_]
  bypass := app.bypassHydraRoutes[_]
  operation := bypass.operations[_]
  path := operation.paths[_]
  sensitive_paths[path]
  msg := {
    "msg": sprintf("App '%s' has sensitive keyword in bypassHydraRoutes path: '%s'", [app.name, path]),
    "severity": "LOW",
    "_loc": {"file": data.conftest.file.name, "line": 1}
  }
}
