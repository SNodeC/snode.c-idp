# Repository-owned package builds

`packages.json` uses schema 2. `find_package(snodec REQUIRED COMPONENTS ...)`
in `CMakeLists.txt` specifies no version constraint, so its declared range is
`>=0.0.0`. This conversion does not change source requirements or target lists.
The existing family dependency lists are unchanged; Rocky 9 adds its compiler
through `rpm@rocky-9` and the native hook activates it.

The chain supplies tagged source and submodules in `SOURCE_DIR`, CI assets in
`CI_DIR`, and exact dependency selections in `DEPENDENCIES_JSON`. The native hook
overrides CPack's project configuration with `$CI_DIR/package/config.cmake`, so a
packaging correction can build the unchanged tag. Local CPack uses that same
configuration file. Client development packages retain their existing dependency
names and record the exact SNode.C version/revision used by the wave;
server development packages retain their exact matching client dependency.
