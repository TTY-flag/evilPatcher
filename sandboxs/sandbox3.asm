A = sys_number
A >= 0x40000000 ? dead : next
A == socket ? dead : next
A == connect ? dead : next
A == bind ? dead : next
A == listen ? dead : next
A == clone ? dead : next
A == execve ? dead : next
return ALLOW
dead:
return KILL
