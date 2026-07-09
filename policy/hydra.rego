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
  "/cleanup/debug/*",
  "/schedule/debug/pprof/*",
  "/worker/debug/pprof/*"
}

deny contains msg if {
  app := input.apps[_]
  bypass := app.bypassHydraRoutes[_]
  operation := bypass.operations[_]
  path := operation.paths[_]
  denied_paths[path]
  msg := {
    "msg": sprintf("App '%s' has denied keyword in bypassHydraRoutes path: '%s'", [app.name, path]),
    "severity": "HIGH",
    "_loc": {"row": 1}
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
    "_loc": {"row": 1}
  }
}

