// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v4.25.0
// source: identity.proto

package identity

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	Identity_IssueTokens_FullMethodName        = "/identity.Identity/IssueTokens"
	Identity_RefreshToken_FullMethodName       = "/identity.Identity/RefreshToken"
	Identity_SetUserPermissions_FullMethodName = "/identity.Identity/SetUserPermissions"
	Identity_GetUserPermissions_FullMethodName = "/identity.Identity/GetUserPermissions"
)

// IdentityClient is the client API for Identity service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type IdentityClient interface {
	IssueTokens(ctx context.Context, in *IssueTokensRequest, opts ...grpc.CallOption) (*MultipleTokensReply, error)
	RefreshToken(ctx context.Context, in *TokenRequest, opts ...grpc.CallOption) (*TokenReply, error)
	SetUserPermissions(ctx context.Context, in *SetUserPermissionsRequest, opts ...grpc.CallOption) (*SetUserPermissionsReply, error)
	GetUserPermissions(ctx context.Context, in *GetUserPermissionsRequest, opts ...grpc.CallOption) (*UserWithPermissions, error)
}

type identityClient struct {
	cc grpc.ClientConnInterface
}

func NewIdentityClient(cc grpc.ClientConnInterface) IdentityClient {
	return &identityClient{cc}
}

func (c *identityClient) IssueTokens(ctx context.Context, in *IssueTokensRequest, opts ...grpc.CallOption) (*MultipleTokensReply, error) {
	out := new(MultipleTokensReply)
	err := c.cc.Invoke(ctx, Identity_IssueTokens_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *identityClient) RefreshToken(ctx context.Context, in *TokenRequest, opts ...grpc.CallOption) (*TokenReply, error) {
	out := new(TokenReply)
	err := c.cc.Invoke(ctx, Identity_RefreshToken_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *identityClient) SetUserPermissions(ctx context.Context, in *SetUserPermissionsRequest, opts ...grpc.CallOption) (*SetUserPermissionsReply, error) {
	out := new(SetUserPermissionsReply)
	err := c.cc.Invoke(ctx, Identity_SetUserPermissions_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *identityClient) GetUserPermissions(ctx context.Context, in *GetUserPermissionsRequest, opts ...grpc.CallOption) (*UserWithPermissions, error) {
	out := new(UserWithPermissions)
	err := c.cc.Invoke(ctx, Identity_GetUserPermissions_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// IdentityServer is the server API for Identity service.
// All implementations must embed UnimplementedIdentityServer
// for forward compatibility
type IdentityServer interface {
	IssueTokens(context.Context, *IssueTokensRequest) (*MultipleTokensReply, error)
	RefreshToken(context.Context, *TokenRequest) (*TokenReply, error)
	SetUserPermissions(context.Context, *SetUserPermissionsRequest) (*SetUserPermissionsReply, error)
	GetUserPermissions(context.Context, *GetUserPermissionsRequest) (*UserWithPermissions, error)
	mustEmbedUnimplementedIdentityServer()
}

// UnimplementedIdentityServer must be embedded to have forward compatible implementations.
type UnimplementedIdentityServer struct {
}

func (UnimplementedIdentityServer) IssueTokens(context.Context, *IssueTokensRequest) (*MultipleTokensReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method IssueTokens not implemented")
}
func (UnimplementedIdentityServer) RefreshToken(context.Context, *TokenRequest) (*TokenReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RefreshToken not implemented")
}
func (UnimplementedIdentityServer) SetUserPermissions(context.Context, *SetUserPermissionsRequest) (*SetUserPermissionsReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SetUserPermissions not implemented")
}
func (UnimplementedIdentityServer) GetUserPermissions(context.Context, *GetUserPermissionsRequest) (*UserWithPermissions, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetUserPermissions not implemented")
}
func (UnimplementedIdentityServer) mustEmbedUnimplementedIdentityServer() {}

// UnsafeIdentityServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to IdentityServer will
// result in compilation errors.
type UnsafeIdentityServer interface {
	mustEmbedUnimplementedIdentityServer()
}

func RegisterIdentityServer(s grpc.ServiceRegistrar, srv IdentityServer) {
	s.RegisterService(&Identity_ServiceDesc, srv)
}

func _Identity_IssueTokens_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(IssueTokensRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IdentityServer).IssueTokens(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Identity_IssueTokens_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IdentityServer).IssueTokens(ctx, req.(*IssueTokensRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Identity_RefreshToken_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(TokenRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IdentityServer).RefreshToken(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Identity_RefreshToken_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IdentityServer).RefreshToken(ctx, req.(*TokenRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Identity_SetUserPermissions_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SetUserPermissionsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IdentityServer).SetUserPermissions(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Identity_SetUserPermissions_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IdentityServer).SetUserPermissions(ctx, req.(*SetUserPermissionsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Identity_GetUserPermissions_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetUserPermissionsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IdentityServer).GetUserPermissions(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Identity_GetUserPermissions_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IdentityServer).GetUserPermissions(ctx, req.(*GetUserPermissionsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Identity_ServiceDesc is the grpc.ServiceDesc for Identity service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Identity_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "identity.Identity",
	HandlerType: (*IdentityServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "IssueTokens",
			Handler:    _Identity_IssueTokens_Handler,
		},
		{
			MethodName: "RefreshToken",
			Handler:    _Identity_RefreshToken_Handler,
		},
		{
			MethodName: "SetUserPermissions",
			Handler:    _Identity_SetUserPermissions_Handler,
		},
		{
			MethodName: "GetUserPermissions",
			Handler:    _Identity_GetUserPermissions_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "identity.proto",
}
