from django.contrib import admin

from .models import Organisation, Membership, Invitation, PlatformAdmin, AuditLog


class MembershipInline(admin.TabularInline):
    """Manage an organisation's members (and assign its owner) inline."""
    model = Membership
    extra = 1
    autocomplete_fields = ['user']


@admin.register(Organisation)
class OrganisationAdmin(admin.ModelAdmin):
    list_display = ['name', 'slug', 'created_at']
    search_fields = ['name', 'slug']
    prepopulated_fields = {'slug': ('name',)}
    inlines = [MembershipInline]


@admin.register(Membership)
class MembershipAdmin(admin.ModelAdmin):
    list_display = ['user', 'organisation', 'role', 'created_at']
    list_filter = ['role', 'organisation']
    search_fields = ['user__username', 'user__email', 'organisation__name']
    autocomplete_fields = ['user', 'organisation']


@admin.register(Invitation)
class InvitationAdmin(admin.ModelAdmin):
    list_display = ['email', 'organisation', 'role', 'accepted', 'created_at', 'expires_at']
    list_filter = ['role', 'accepted', 'organisation']
    search_fields = ['email', 'organisation__name']
    readonly_fields = ['token', 'created_at']


@admin.register(PlatformAdmin)
class PlatformAdminAdmin(admin.ModelAdmin):
    list_display = ['user', 'note', 'created_at']
    search_fields = ['user__username', 'user__email']
    autocomplete_fields = ['user']


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ['created_at', 'action', 'actor_email', 'organisation', 'target']
    list_filter = ['action', 'organisation']
    search_fields = ['actor_email', 'target', 'action']
    readonly_fields = ['organisation', 'actor', 'actor_email', 'action', 'target',
                       'metadata', 'ip_address', 'created_at']
    date_hierarchy = 'created_at'
