#### Bazel Overrides

The bazel build configuration in this repo works as is (it better!)...however it required several workarounds due to the way bazel's `rules_go` works with generated google api protos.  


In this repo, the `go_repository{}` requires the following overrides with `build_file_proto_mode = "disable_global"`:

```bazel
load("@bazel_gazelle//:deps.bzl", "go_repository")

def go_repositories():
    go_repository(
        name = "com_github_googleapis_gax_go_v2",
        importpath = "github.com/googleapis/gax-go/v2",
        build_file_proto_mode = "disable_global",
        sum = "h1:A+gCJKdRfqXkr+BIRGtZLibNXf0m1f9E4HG56etFpas=",
        version = "v2.12.0",
    )

    go_repository(
        name = "org_golang_google_appengine",
        importpath = "google.golang.org/appengine",
        build_file_proto_mode = "disable_global",
        sum = "h1:FZR1q0exgwxzPzp/aF+VccGrSfxfPpkBqjIIEq3ru6c=",
        version = "v1.6.7",
    )
```

---

 (reference: [bazelbuild/rules_go#3467](https://gist.github.com/salrashid123/8e81645454d5aebdc04fd78831310cf1))