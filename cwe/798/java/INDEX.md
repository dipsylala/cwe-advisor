# CWE-798: Use of Hard-coded Credentials - Java

## LLM Guidance

A hard-coded credential in Java survives compilation: the JVM specification stores a string literal in the class file's constant pool as a `CONSTANT_String_info` pointing at a `CONSTANT_Utf8_info`, so the characters are readable from the artifact without decompiling anything. Most findings are *outbound* - a value the application sends to a database or service - and the fix is to resolve it at runtime. Check first whether the literal is one the application *accepts*, since that is a backdoor no secret store fixes. Rotate before refactoring, and check the built JAR as well as the source.

## Key Principles

- Removing the default from `@Value("${db.password:changeit}")` does not fail closed. Spring's default resolver is lenient: an unresolvable placeholder is injected as its own text, so the field receives the literal string `${db.password}` and the application starts with that as the password. Declaring a `PropertySourcesPlaceholderConfigurer` bean is what makes an unresolved placeholder a startup failure
- `${DB_PASSWORD}` in `application.properties` works because those files are "filtered through the existing `Environment`" when read, which includes OS environment variables. Precedence is the part worth checking: config data is consulted *before* environment variables and system properties, and later sources win, so an exported value overrides the committed file rather than the other way round
- Spring Boot states it "does not provide any built-in support for encrypting property values", offering only `EnvironmentPostProcessor` as a hook and naming Spring Cloud Vault as the supported answer - so "encrypted configuration" is not a first-party option to reach for here
- Name the integration artifact so its version can be checked, and note the AWS one moved: `io.awspring.cloud:spring-cloud-aws-starter-secrets-manager` (4.x) replaced `org.springframework.cloud:spring-cloud-starter-aws-secrets-manager-config`, whose last release was February 2021. It is wired with `spring.config.import=aws-secretsmanager:/secrets/name`. Azure is `com.azure.spring:spring-cloud-azure-starter-keyvault` with a BOM matched to the Boot line (7.4.0 for Boot 4.0.x, 6.5.0 for 3.5.x); Vault is `org.springframework.cloud:spring-cloud-starter-vault-config`
- `PasswordAuthentication` takes `(String userName, char[] password)` - there is no no-argument form. The array is cloned on construction and `getPassword()` hands back a live reference the caller is expected to zero, which a `String` literal can never support
- A build can inject the secret for you: with `spring-boot-starter-parent`, Maven resource filtering expands `@...@` placeholders in `application.properties`, which puts the resolved value inside the JAR. If the project sets `useDefaultDelimiters` to anything but `false`, the build also expands ordinary `${...}` Spring placeholders, silently baking in what was meant to resolve at runtime
- A JDK `KeyStore` can hold an arbitrary secret as a `SecretKeyEntry`, and `pkcs12` has been the default and recommended type since JDK 9 where `jceks` is documented as proprietary - but the store itself opens with a password, so it relocates the bootstrapping problem rather than removing it

## Taint Sinks

`DriverManager.getConnection(url, user, password)` with a literal, `new PasswordAuthentication(user, password)`, `Properties.setProperty("password", ...)` passed to `getConnection(url, Properties)`, `@Value("${secret:default}")` with a credential as the default, a literal compared in an authentication path, real values in a committed profile properties file, `Dockerfile` `ENV` line or Kubernetes manifest

## Remediation Steps

- Locate - Search source, every `application-*.properties`/`.yaml` profile, deployment manifests, and the built JAR; a value moved from code into a committed profile file is the same finding one file over
- Confirm the direction - A literal compared against user input needs deletion and per-installation enrolment rather than relocation
- Rotate first - GitHub's own guidance puts revoke-and-rotate before any history rewrite, and notes that once the credential is rotated, rewriting history "may not be warranted"
- Replace the read - Resolve from a named starter above, or from the environment, and add a `PropertySourcesPlaceholderConfigurer` so a missing value stops startup instead of arriving as placeholder text
- Rewrite history only if still needed - `git filter-repo` is what git's own documentation recommends over `filter-branch`; GitHub's flow needs its `--sensitive-data-removal` flag, which requires version 2.47 or later
- Untrack, do not just ignore - Adding a properties file to `.gitignore` leaves an already-tracked file tracked; `git rm --cached` is what removes it
- Test - Confirm the application starts with the value supplied externally, fails clearly when it is absent, and that unzipping the JAR and grepping the packaged properties finds nothing
