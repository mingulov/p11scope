# The deterministic version-matrix oracle for p11scope-discover, in one place:
# both container lanes and the unprivileged --self-test run this exact filter.
def full($major; $minor; $count):
  any(.surfaces[]; .version == {major:$major, minor:$minor}
      and .walk.status == "full" and (.functions | length) == $count);
full(2;40;68) and full(3;0;92) and full(3;1;92) and full(3;2;104)
and any(.surfaces[]; .source.classification == "corroborated_standard_prefix"
        and .source.name_lossy == "Acme Standard ABI" and (.functions | length) == 104)
and any(.surfaces[]; .source.classification == "corroborated_standard_prefix"
        and .source.name_error == "null name pointer" and (.functions | length) == 92)
and any(.vendor_interfaces[]; .name_lossy == "Vendor Pretend")
