A = sys_number
A >= 0x40000000 ? dead : next
A == open ? dead : next
A == mmap ? dead : next
A == ptrace ? dead : next
A == openat ? dead : next
A == open_by_handle_at ? dead : next
return ALLOW
dead:
return KILL
