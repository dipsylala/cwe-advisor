# CWE-917: Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection') - Java

## LLM Guidance

Java carries most reported EL injection, and the deliberate-evaluation cases are covered elsewhere: CWE-94 holds the SpEL evaluation contexts and their CVE floors, and CWE-95 holds OGNL with `SecurityMemberAccess`, `struts.allowlist.enable` and the S2 bypass history. Use this entry for the case where nothing in the application evaluates anything - Bean Validation message interpolation, a JSP or JSF page rendering a value into `${...}`, a label or rule body stored as data and interpolated on display.

## Key Principles

- Bean Validation is the common finding and its default is safe. On Hibernate Validator 8.0.1 a custom violation template is not EL-interpolated at all: `buildConstraintViolationWithTemplate(userText)` with `${1+1}` emits `${1+1}` unchanged. The defect is `customViolationExpressionLanguageFeatureLevel` having been raised, so read the configuration before the validator
- The levels are not equivalent and only the top one executes. `VARIABLES` and `BEAN_PROPERTIES` evaluate `${1+1}` to `2` but refuse method calls, logging `HV000264` and emitting the template unchanged; `BEAN_METHODS` evaluates `${''.getClass().forName('java.lang.Runtime')}` to `class java.lang.Runtime`. A finding at `VARIABLES` is real but is not execution
- **`addMessageParameter` is not the safe one, despite reading like the parameterized form.** Message parameters are substituted into the template *before* EL runs, so at `BEAN_METHODS` a static template `"rejected: {v}"` with the payload bound to `v` still returns `rejected: class java.lang.Runtime`. `addExpressionVariable` with `"rejected: ${v}"` is the one that holds, because the variable resolves to a value that is not re-parsed
- Neither is correct on its own, so pick by the configuration. With EL disabled - the default - `addMessageParameter` renders the value literally and is right, while `addExpressionVariable` emits the literal `${v}` and warns `HV000257`, a silent message regression. With EL enabled, that reverses. Prefer restoring the default and using message parameters over keeping EL on and switching API
- A value interpolated into a message is not interpolated again, so `{validatedValue}` carrying `${1+1}` renders `${1+1}`; the exposure is the template, not the data bound into it
- In a JSP or JSF page the second parse is the container's: a value written into the page that still contains `${...}` or `#{...}` is evaluated on render, so escape for the EL context as well as for HTML, and do not reach for a servlet-level filter that strips `$` - it corrupts legitimate currency and regex values

## Taint Sinks

`ConstraintValidatorContext.buildConstraintViolationWithTemplate()`, `customViolationExpressionLanguageFeatureLevel()`, `constraintExpressionLanguageFeatureLevel()`, `MessageInterpolator.interpolate()`, `ExpressionFactory.createValueExpression()`, `ValueExpression.getValue()`, `Application.evaluateExpressionGet()`

## Remediation Steps

- Locate - find the interpolating layer: a `ConstraintValidator` calling `buildConstraintViolationWithTemplate`, a JSP or JSF page rendering a stored value, or a message bundle entry built from input
- Read the configuration - check `customViolationExpressionLanguageFeatureLevel` and `constraintExpressionLanguageFeatureLevel` on the `HibernateValidatorConfiguration` and in `META-INF/validation.xml`, and record what each is set to before changing anything
- Identify the unsafe pattern - untrusted text reaching the template argument, or reaching a message parameter while EL is enabled for custom violations
- Replace with the safe pattern - keep the template a constant, restore the custom-violation level to the default so EL does not run on it, and bind the value with `addMessageParameter`; where EL must stay enabled for that position, bind with `addExpressionVariable` and a `${...}` placeholder instead
- Break taint after allowlist validation - where the message must name a permitted value, emit the matched constant from the allowlist rather than the submitted string
- Add secondary controls - run with least privilege, and do not expose the validated bean's own methods through the evaluation context
- Test - assert on `ConstraintViolation.getMessage()` rather than on an exception: a disabled feature logs `HV000264` and returns the template unchanged, so a throws-assertion passes whether or not the fix is wired. Confirm `${1+1}` appears literally and that a legitimate value still appears in the message, which catches the `HV000257` case where the placeholder never resolved
