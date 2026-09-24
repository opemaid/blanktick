import com.blanktick.desktop.collect.Shell;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;

/**
 * Runs Blanktick's real binary-resolution guard on a real POSIX machine.
 *
 * ## Why this exists rather than a unit test
 *
 * The guard decides whether a system tool could have been planted by an
 * unprivileged process, and that question is answered by the filesystem, not by
 * the code: where a distribution puts `ss`, whether `/usr/local/bin` belongs to
 * root or to the logged-in user, what Homebrew has done to `/usr/local`. None
 * of that is knowable from a Windows build machine, and the author of this code
 * has no Mac and no native Linux install — so the POSIX half of the guard
 * shipped reasoned rather than run.
 *
 * This closes that gap without pretending to. It loads the **compiled Kotlin**
 * from `desktop/build/classes/kotlin/main` — the same bytecode the application
 * runs, not a reimplementation of it — and calls `Shell.resolve` on a genuine
 * POSIX filesystem. JVM bytecode is portable even though the toolchain that
 * produced it is not, which is what makes this possible on a machine with no
 * Kotlin compiler and no JDK 17.
 *
 * Run it wherever you have a POSIX box:
 *
 *   javac -cp <classes>:<kotlin-stdlib.jar> -d /tmp/rc tools/LinuxResolveCheck.java
 *   java  -cp /tmp/rc:<classes>:<kotlin-stdlib.jar> LinuxResolveCheck
 *
 * Exits non-zero if the guard would accept something an ordinary user can
 * overwrite.
 */
public class LinuxResolveCheck {

    private static int failures = 0;

    private static void check(boolean condition, String what) {
        System.out.printf("  [%s] %s%n", condition ? "PASS" : "FAIL", what);
        if (!condition) failures++;
    }

    public static void main(String[] args) throws Exception {
        System.out.println("Blanktick resolve() on " + System.getProperty("os.name")
                + " (" + System.getProperty("os.version") + "), user "
                + System.getProperty("user.name"));
        System.out.println("=".repeat(72));

        // ---- 1. the tools the Linux collector actually calls ---------------
        System.out.println("\n1. Tools the Linux collector invokes");
        String[] tools = {
            "id", "lsof", "lsblk", "ss", "systemctl",
            "resolvectl", "gsettings", "nft", "ufw", "mokutil"
        };
        int resolved = 0;
        for (String t : tools) {
            String where = Shell.INSTANCE.resolve(t);
            boolean installed = onPath(t);
            System.out.printf("   %-12s %s%n", t,
                where != null ? where : (installed
                    ? "NOT RESOLVED but IS installed  <-- trusted-dir list is wrong"
                    : "not resolved (not installed on this box)"));
            if (where != null) resolved++;
            // The failure that matters: present on the system, refused by us.
            check(!(installed && where == null),
                t + ": installed tools must resolve");
        }
        System.out.println("   " + resolved + " of " + tools.length + " resolved.");

        // ---- 2. every resolved path is genuinely root-owned ---------------
        System.out.println("\n2. Resolved paths are root-owned and not group/world-writable");
        for (String t : tools) {
            String where = Shell.INSTANCE.resolve(t);
            if (where == null) continue;
            Path p = Paths.get(where).toRealPath();
            boolean safe = true;
            String offender = null;
            for (Path cur = p; cur != null; cur = cur.getParent()) {
                PosixFileAttributes a =
                    Files.readAttributes(cur, PosixFileAttributes.class);
                boolean ok = a.owner().getName().equals("root")
                    && !a.permissions().contains(PosixFilePermission.GROUP_WRITE)
                    && !a.permissions().contains(PosixFilePermission.OTHERS_WRITE);
                if (!ok) { safe = false; offender = cur + " owned by " + a.owner().getName(); break; }
            }
            check(safe, t + " -> " + where + (safe ? "" : "  [" + offender + "]"));
        }

        // ---- 3. the attack itself: a planted binary on PATH ---------------
        System.out.println("\n3. A binary planted in a user-writable directory");
        Path evilDir = Files.createTempDirectory("blanktick-hijack-");
        try {
            Path evil = evilDir.resolve("id");
            Files.writeString(evil, "#!/bin/sh\necho PWNED\n");
            evil.toFile().setExecutable(true);

            check(Shell.INSTANCE.resolve(evil.toAbsolutePath().toString()) == null,
                "an absolute path into a temp dir is refused");
            check(Shell.INSTANCE.resolve("blanktick-not-a-real-tool") == null,
                "an unknown tool name resolves to nothing");

            String realId = Shell.INSTANCE.resolve("id");
            check(realId == null || realId.startsWith("/usr") || realId.startsWith("/bin"),
                "`id` resolves to a system path, not to the planted copy");

            // 4. root-owned file inside a world-writable directory: the file
            //    itself is fine, but it can be unlinked and replaced, which is
            //    why the guard walks upwards.
            System.out.println("\n4. World-writable parent directory");
            Path openDir = Files.createTempDirectory("blanktick-openperm-");
            try {
                Files.setPosixFilePermissions(openDir,
                    PosixFilePermissions.fromString("rwxrwxrwx"));
                Path tool = openDir.resolve("lsof");
                Files.writeString(tool, "#!/bin/sh\n");
                tool.toFile().setExecutable(true);
                check(Shell.INSTANCE.resolve(tool.toAbsolutePath().toString()) == null,
                    "a tool under a world-writable directory is refused");
            } finally {
                deleteTree(openDir.toFile());
            }
        } finally {
            deleteTree(evilDir.toFile());
        }

        // ---- 5. and it still actually runs a real command ------------------
        System.out.println("\n5. A resolved tool still executes");
        String out = Shell.INSTANCE.stdout(new String[]{"id", "-un"}, 20L);
        check(out != null && !out.isBlank(), "`id -un` returned: "
            + (out == null ? "null" : out.trim()));

        System.out.println("\n" + "=".repeat(72));
        System.out.println(failures == 0
            ? "ALL CHECKS PASSED"
            : failures + " CHECK(S) FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }

    /** Whether the tool exists anywhere on PATH, regardless of whether we trust it. */
    private static boolean onPath(String tool) {
        String path = System.getenv("PATH");
        if (path == null) return false;
        for (String dir : path.split(File.pathSeparator)) {
            File f = new File(dir, tool);
            if (f.isFile() && f.canExecute()) return true;
        }
        return false;
    }

    private static void deleteTree(File f) {
        File[] kids = f.listFiles();
        if (kids != null) for (File k : kids) deleteTree(k);
        f.delete();
    }
}
