package main

deny contains msg if {
  app := input.apps[_]
  bypass := app.bypassHydraRoutes[_]
  operation := bypass.operations[_]
  path := operation.paths[_]
  contains(path, "*")
  msg := {
    "msg": sprintf("App '%s' has wildcard in bypassHydraRoutes path: '%s'", [app.name, path]),
    "severity": "HIGH",
    "_loc": {"row": 1}
  }
}
