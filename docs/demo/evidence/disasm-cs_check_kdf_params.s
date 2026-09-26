     c20:	push   %r14
     c22:	push   %r13
     c24:	mov    $0x1,%r13d
     c2a:	push   %r12
     c2c:	mov    %esi,%r12d
     c2f:	push   %rbp
     c30:	lea    0xc24(%rdi),%rbp
     c37:	push   %rbx
     c38:	xor    %ebx,%ebx
     c3a:	sub    $0x10,%rsp
     c3e:	jmp    c6f <cs_check_kdf_params+0x4f>
     c40:	mov    0xc(%rsp),%edx
     c44:	cmp    %edx,%eax
     c46:	jae    caa <cs_check_kdf_params+0x8a>
     c48:	sub    $0x927c0,%r14d
     c4f:	cmp    $0x17ce5c40,%r14d
     c56:	ja     caa <cs_check_kdf_params+0x8a>
     c58:	nopl   0x0(%rax,%rax,1)
     c60:	add    $0x1,%ebx
     c63:	add    $0x9c,%rbp
     c6a:	cmp    $0x8,%ebx
     c6d:	je     cc8 <cs_check_kdf_params+0xa8>
     c6f:	mov    %r13d,%eax
     c72:	mov    %ebx,%ecx
     c74:	shl    %cl,%eax
     c76:	test   %r12d,%eax
     c79:	je     c60 <cs_check_kdf_params+0x40>
     c7b:	cmpw   $0x1,-0x2(%rbp)
     c80:	jne    c60 <cs_check_kdf_params+0x40>
     c82:	mov    0x0(%rbp),%r14d
     c86:	call   b70 <cs_jitter.isra.0>
     c8b:	test   %al,%al
     c8d:	je     caa <cs_check_kdf_params+0x8a>
     c8f:	movl   $0x927c0,0x8(%rsp)
     c97:	mov    0x0(%rbp),%eax
     c9a:	movl   $0x17d78401,0xc(%rsp)
     ca2:	mov    0x8(%rsp),%edx
     ca6:	cmp    %edx,%eax
     ca8:	jae    c40 <cs_check_kdf_params+0x20>
     caa:	add    $0x10,%rsp
     cae:	xor    %eax,%eax
     cb0:	pop    %rbx
     cb1:	pop    %rbp
     cb2:	pop    %r12
     cb4:	pop    %r13
     cb6:	pop    %r14
     cb8:	xor    %edx,%edx
     cba:	xor    %ecx,%ecx
     cbc:	xor    %esi,%esi
     cbe:	xor    %edi,%edi
     cc0:	ret
     cc1:	nopl   0x0(%rax)
     cc8:	add    $0x10,%rsp
     ccc:	mov    $0x1,%eax
     cd1:	pop    %rbx
     cd2:	pop    %rbp
     cd3:	pop    %r12
     cd5:	pop    %r13
     cd7:	pop    %r14
     cd9:	xor    %edx,%edx
     cdb:	xor    %ecx,%ecx
     cdd:	xor    %esi,%esi
     cdf:	xor    %edi,%edi
     ce1:	ret
