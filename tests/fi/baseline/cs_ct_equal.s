  endbr64
  movb   $0x0,-0x1(%rsp)
  test   %rdx,%rdx
  je X
  xor    %ecx,%ecx
  movzbl -0x1(%rsp),%r8d
  movzbl (%rdi,%rcx,1),%eax
  xor    (%rsi,%rcx,1),%al
  add    $0x1,%rcx
  or     %r8d,%eax
  mov    %al,-0x1(%rsp)
  cmp    %rcx,%rdx
  jne X
  movzbl -0x1(%rsp),%eax
  test   %eax,%eax
  sete   %al
  xor    %edx,%edx
  xor    %ecx,%ecx
  xor    %esi,%esi
  xor    %edi,%edi
  xor    %r8d,%r8d
  ret
