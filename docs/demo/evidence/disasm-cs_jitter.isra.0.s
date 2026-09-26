     b70:	sub    $0x28,%rsp
     b74:	xor    %edx,%edx
     b76:	mov    $0x4,%esi
     b7b:	mov    %fs:0x28,%rax
     b84:	mov    %rax,0x18(%rsp)
     b89:	xor    %eax,%eax
     b8b:	lea    0xc(%rsp),%rdi
     b90:	movl   $0x0,0xc(%rsp)
     b98:	call   b9d <cs_jitter.isra.0+0x2d>
			b99: R_X86_64_PLT32	qcrypto_random_bytes-0x4
     b9d:	mov    0xc(%rsp),%edx
     ba1:	and    $0x3fff,%edx
     ba7:	add    $0x400,%edx
     bad:	mov    %edx,0x10(%rsp)
     bb1:	mov    %edx,0x14(%rsp)
     bb5:	mov    0x10(%rsp),%eax
     bb9:	test   %eax,%eax
     bbb:	je     bd4 <cs_jitter.isra.0+0x64>
     bbd:	nopl   (%rax)
     bc0:	nop
     bc1:	mov    0x10(%rsp),%eax
     bc5:	sub    $0x1,%eax
     bc8:	mov    %eax,0x10(%rsp)
     bcc:	mov    0x10(%rsp),%eax
     bd0:	test   %eax,%eax
     bd2:	jne    bc0 <cs_jitter.isra.0+0x50>
     bd4:	mov    0x10(%rsp),%eax
     bd8:	xor    %ecx,%ecx
     bda:	test   %eax,%eax
     bdc:	je     c00 <cs_jitter.isra.0+0x90>
     bde:	mov    0x18(%rsp),%rax
     be3:	sub    %fs:0x28,%rax
     bec:	jne    c13 <cs_jitter.isra.0+0xa3>
     bee:	mov    %ecx,%eax
     bf0:	add    $0x28,%rsp
     bf4:	xor    %edx,%edx
     bf6:	xor    %ecx,%ecx
     bf8:	xor    %esi,%esi
     bfa:	xor    %edi,%edi
     bfc:	ret
     bfd:	nopl   (%rax)
     c00:	mov    0x14(%rsp),%eax
     c04:	cmp    %edx,%eax
     c06:	jne    bde <cs_jitter.isra.0+0x6e>
     c08:	mov    0x10(%rsp),%eax
     c0c:	test   %eax,%eax
     c0e:	sete   %cl
     c11:	jmp    bde <cs_jitter.isra.0+0x6e>
     c13:	call   c18 <cs_jitter.isra.0+0xa8>
			c14: R_X86_64_PLT32	__stack_chk_fail-0x4
