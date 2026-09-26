  50:	endbr64
  54:	movl   $0x0,-0x4(%rsp)
  5c:	test   %rdx,%rdx
  5f:	je     85 <cs_ct_equal_alt+0x35>
  61:	nopl   0x0(%rax)
  68:	sub    $0x1,%rdx
  6c:	mov    -0x4(%rsp),%ecx
  70:	movzbl (%rdi,%rdx,1),%eax
  74:	sub    (%rsi,%rdx,1),%al
  77:	movzbl %al,%eax
  7a:	or     %ecx,%eax
  7c:	mov    %eax,-0x4(%rsp)
  80:	test   %rdx,%rdx
  83:	jne    68 <cs_ct_equal_alt+0x18>
  85:	mov    -0x4(%rsp),%eax
  89:	test   %eax,%eax
  8b:	sete   %al
  8e:	xor    %edx,%edx
  90:	xor    %ecx,%ecx
  92:	xor    %esi,%esi
  94:	xor    %edi,%edi
  96:	ret
