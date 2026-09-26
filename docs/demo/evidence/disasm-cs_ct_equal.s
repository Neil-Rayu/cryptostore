   0:	endbr64
   4:	movb   $0x0,-0x1(%rsp)
   9:	test   %rdx,%rdx
   c:	je     2d <cs_ct_equal+0x2d>
   e:	xor    %ecx,%ecx
  10:	movzbl -0x1(%rsp),%r8d
  16:	movzbl (%rdi,%rcx,1),%eax
  1a:	xor    (%rsi,%rcx,1),%al
  1d:	add    $0x1,%rcx
  21:	or     %r8d,%eax
  24:	mov    %al,-0x1(%rsp)
  28:	cmp    %rcx,%rdx
  2b:	jne    10 <cs_ct_equal+0x10>
  2d:	movzbl -0x1(%rsp),%eax
  32:	test   %eax,%eax
  34:	sete   %al
  37:	xor    %edx,%edx
  39:	xor    %ecx,%ecx
  3b:	xor    %esi,%esi
  3d:	xor    %edi,%edi
  3f:	xor    %r8d,%r8d
  42:	ret
