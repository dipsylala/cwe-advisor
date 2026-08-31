# Findings for the `docs/` corpus

Suggested changes to `docs/`, and nothing else. `docs/` is gitignored here and maintained
elsewhere, so this file is the hand-off channel rather than a change set applied directly.

## CWE-915/java/index.md

- Line 169: "`WebDataBinder` handles `@ModelAttribute` and `@RequestParam` binding from form
  fields, query string, and path variables" overstates what `setAllowedFields()`/
  `setDisallowedFields()` actually restrict. Those allowlist/denylist methods gate property
  binding onto a target bean via `WebDataBinder.bind()`, which only happens for `@ModelAttribute`
  targets. `@RequestParam` and `@PathVariable` are resolved as direct method arguments by their
  own `HandlerMethodArgumentResolver`s (not bound onto an object graph), so `setAllowedFields()`
  has no effect on them even though a `WebDataBinder`/`ConversionService` may still perform simple
  type conversion for those arguments. Recommend narrowing the sentence to `@ModelAttribute`
  (and classic form-backing objects) only, to avoid implying the allowlist also covers
  `@RequestParam`/`@PathVariable` parameters.

## CWE-915/ruby/index.md

- Line 66 (Legacy note): "That mechanism was removed from Rails 4.0 onward; if you see it in a
  codebase, the application is on an unsupported Rails version and needs a broader upgrade" is
  wrong. `attr_accessible`/`attr_protected` were extracted from Rails core into the separate
  `protected_attributes` gem, which can be (and sometimes still is) installed on top of Rails 4+
  to restore the old behavior - it is not core-removed-therefore-unsupported-version evidence.
  Finding `attr_accessible` in a Rails 4+ app means that gem is present (the gem itself is
  unmaintained and worth flagging on its own), not that the app is running an unsupported Rails
  version. Recommend replacing the inference with: check the Gemfile for `protected_attributes`;
  if present, remove it and migrate to Strong Parameters; the Rails version itself may be current.

## CWE-915/php/index.md

- Line 7: "Models missing both `$fillable` and `$guarded` may throw a `MassAssignmentException`
  in development but expose all attributes if the protection is disabled via `Model::unguard()`"
  wrongly gates the exception on environment. Eloquent's `fill()` throws `MassAssignmentException`
  for a totally-guarded model (`totallyGuarded()`: `$guarded === ['*']` and `$fillable` empty,
  which is the default when neither property is set) unconditionally - the check is not
  `app()->environment()`-gated, so it throws in production exactly as it does locally. The
  `Model::unguard()` half of the sentence is correct (that call disables the check process-wide).
  Recommend dropping "in development" or rephrasing to state the throw is unconditional absent
  `unguard()`.

## CWE-114/python/index.md

- Line 1001-1002 (Considerations): "on Linux, `/proc/sys/kernel/pid_max` defaults to 4194304 on
  64-bit but is often left at 32768" has the default and the override backwards. The kernel's own
  compiled-in default is 32768 on both 32-bit and 64-bit; it is systemd (via
  `/usr/lib/sysctl.d/50-pid-max.conf` on RHEL8+/CentOS/Ubuntu and similar modern distros) that
  raises it to 4194304. So a host is more likely to sit at the *raised* systemd value than to
  have been "left at" 32768 - the sentence describes the relationship as the reverse of how it
  actually happens. The surrounding point (PIDs recycle quickly enough on a busy host that
  allowlisting via the application's own record, not the PID's numeric range, is the real
  control) is unaffected and still correct; only the specific default/override attribution needs
  correcting.

## CWE-114/java/index.md

- Lines 409-427 (`SecurePluginLoader.loadPlugin`): the `URLClassLoader` is closed by the
  try-with-resources block before the method returns the instantiated plugin object. `close()`
  releases the jar file the loader was opened against; any class from that jar not yet loaded at
  that point (a helper class, a lambda's synthetic class, anything referenced only from a method
  body that hasn't executed yet) will fail to resolve with `NoClassDefFoundError` /
  `ClassNotFoundException` the first time the caller actually uses the plugin, because the jar is
  already closed. The pattern only works for a plugin whose entire class graph loads eagerly
  during construction, which is not typical. Recommend either not closing the loader until the
  plugin is discarded (track it alongside the instance and close both together) or documenting
  the eager-loading constraint explicitly so a reader doesn't copy this for a multi-class plugin.

## CWE-915/javascript/index.md

- Line 176 (Common Pitfalls): "`fields` only guards updates; creation still needs its own
  allowlist or explicit field list" overstates Sequelize's API. `fields` is a general
  create/update option, not update-only - `Model.create(values, { fields: [...] })` restricts
  which attributes are included in the INSERT the same way it restricts an UPDATE. The pitfall's
  underlying point (a dev added `fields` on the update path and forgot the create path) is still
  valid, but the stated reason is wrong: the risk is forgetting to add the option on create, not
  that the option is incapable of applying there. Recommend rewording to say the fix was applied
  to update but not extended to create, rather than claiming `fields` "only guards updates."

## CWE-114/javascript/index.md

- Line 620: "`isMaster` was renamed `isPrimary` in Node 16 and is deprecated; `isPrimary` on
  Node 18+" is wrong about when the replacement became available. Per the Node.js `cluster`
  docs, `cluster.isPrimary` was added in v16.0.0, the same release that deprecated
  `cluster.isMaster` - there is no version where `isMaster` is deprecated but `isPrimary` is not
  yet available. Recommend replacing "isPrimary on Node 18+" with "isPrimary since Node 16.0.0"
  (or dropping the second clause, since it adds a false version gate rather than new information).
