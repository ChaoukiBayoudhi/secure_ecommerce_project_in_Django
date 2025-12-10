"""
Django admin configuration for monitoring models.
"""

from django.contrib import admin
from .models import (
    HealthMetric,
    Alert,
    Incident,
    AIAgentAction,
    SystemHealth,
)


@admin.register(HealthMetric)
class HealthMetricAdmin(admin.ModelAdmin):
    """Admin interface for HealthMetric."""
    list_display = ['metric_type', 'value', 'unit', 'status', 'timestamp']
    list_filter = ['metric_type', 'status', 'timestamp']
    search_fields = ['metric_type']
    readonly_fields = ['timestamp']
    date_hierarchy = 'timestamp'


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    """Admin interface for Alert."""
    list_display = ['title', 'alert_type', 'severity', 'status', 'ai_action_taken', 'created_at']
    list_filter = ['alert_type', 'severity', 'status', 'ai_action_taken', 'created_at']
    search_fields = ['title', 'message', 'source']
    readonly_fields = ['created_at', 'acknowledged_at', 'resolved_at']
    date_hierarchy = 'created_at'
    
    actions = ['mark_acknowledged', 'mark_resolved']
    
    def mark_acknowledged(self, request, queryset):
        """Mark selected alerts as acknowledged."""
        from django.utils import timezone
        queryset.update(status='acknowledged', acknowledged_at=timezone.now())
    mark_acknowledged.short_description = "Mark selected alerts as acknowledged"
    
    def mark_resolved(self, request, queryset):
        """Mark selected alerts as resolved."""
        from django.utils import timezone
        queryset.update(status='resolved', resolved_at=timezone.now())
    mark_resolved.short_description = "Mark selected alerts as resolved"


@admin.register(Incident)
class IncidentAdmin(admin.ModelAdmin):
    """Admin interface for Incident."""
    list_display = ['title', 'incident_type', 'severity', 'status', 'ai_detected', 'ai_resolved', 'created_at']
    list_filter = ['incident_type', 'severity', 'status', 'ai_detected', 'ai_resolved', 'created_at']
    search_fields = ['title', 'description']
    readonly_fields = ['created_at', 'resolved_at', 'closed_at']
    date_hierarchy = 'created_at'


@admin.register(AIAgentAction)
class AIAgentActionAdmin(admin.ModelAdmin):
    """Admin interface for AIAgentAction."""
    list_display = ['action_type', 'status', 'success', 'triggered_by', 'created_at', 'completed_at']
    list_filter = ['action_type', 'status', 'success', 'created_at']
    search_fields = ['description', 'triggered_by', 'result_message']
    readonly_fields = ['created_at', 'executed_at', 'completed_at']
    date_hierarchy = 'created_at'


@admin.register(SystemHealth)
class SystemHealthAdmin(admin.ModelAdmin):
    """Admin interface for SystemHealth."""
    list_display = ['overall_status', 'api_status', 'database_status', 'cpu_usage', 'memory_usage', 'active_alerts_count', 'timestamp']
    list_filter = ['overall_status', 'api_status', 'database_status', 'timestamp']
    readonly_fields = ['timestamp']
    date_hierarchy = 'timestamp'
