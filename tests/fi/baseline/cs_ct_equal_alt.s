  endbr64
  movl   $0x0,-0x4(%rsp)
  test   %rdx,%rdx
  je X
  nopl   0x0(%rax)
  sub    $0x1,%rdx
  mov    -0x4(%rsp),%ecx
  movzbl (%rdi,%rdx,1),%eax
  sub    (%rsi,%rdx,1),%al
  movzbl %al,%eax
  or     %ecx,%eax
  mov    %eax,-0x4(%rsp)
  test   %rdx,%rdx
  jne X
  mov    -0x4(%rsp),%eax
  test   %eax,%eax
  sete   %al
  xor    %edx,%edx
  xor    %ecx,%ecx
  xor    %esi,%esi
  xor    %edi,%edi
  ret
