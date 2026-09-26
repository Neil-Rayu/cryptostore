  a0:	endbr64
  a4:	push   %rbx
  a5:	mov    %rdi,%r10
  a8:	mov    %ecx,%ebx
  aa:	mov    %rsi,%r9
  ad:	mov    %rdx,%r11
  b0:	call   b5 <cs_tag_verdict+0x15>
			b1: R_X86_64_PLT32	cs_ct_equal-0x4
  b5:	or     %ebx,%eax
  b7:	movzbl %al,%r8d
  bb:	mov    %r11,%rdx
  be:	mov    %r10,%rsi
  c1:	mov    %r9,%rdi
  c4:	call   c9 <cs_tag_verdict+0x29>
			c5: R_X86_64_PLT32	cs_ct_equal_alt-0x4
  c9:	movzbl %al,%edx
  cc:	mov    %r8d,%eax
  cf:	neg    %edx
  d1:	pop    %rbx
  d2:	neg    %eax
  d4:	and    $0xcbef3fcd,%edx
  da:	and    $0xf6d7fbb3,%eax
  df:	xor    %edx,%eax
  e1:	xor    $0xb5afe1c7,%eax
  e6:	xor    %edx,%edx
  e8:	xor    %ecx,%ecx
  ea:	xor    %esi,%esi
  ec:	xor    %edi,%edi
  ee:	xor    %r8d,%r8d
  f1:	xor    %r9d,%r9d
  f4:	xor    %r10d,%r10d
  f7:	xor    %r11d,%r11d
  fa:	ret
