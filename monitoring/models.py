"""
Monitoring Models for Health Monitoring and AI Agent.

This module defines models for comprehensive application monitoring including:
- System health metrics
- Application performance metrics
- Security events
- AI agent actions
- Alerts and incidents
"""

from django.db import models
from django.utils.translation import gettext_lazy as _
from django.core.validators import MinValueValidator, MaxValueValidator

# Use models.JSONField for Django 3.1+, fallback to TextField for older versions
try:
    JSONField = models.JSONField
except AttributeError:
    from django.contrib.postgres.fields import JSONField


class HealthMetric(models.Model):
    """
    System and application health metrics.
    
    Tracks various metrics for monitoring application health:
    - System resources (CPU, memory, disk)
    - Application performance (response time, throughput)
    - Database metrics
    - Security metrics
    """
    
    # Metric Information
    metric_type = models.CharField(
        max_length=50,
        choices=[
            ('cpu', _('CPU Usage')),
            ('memory', _('Memory Usage')),
            ('disk', _('Disk Usage')),
            ('response_time', _('Response Time')),
            ('error_rate', _('Error Rate')),
            ('throughput', _('Throughput')),
            ('db_connections', _('Database Connections')),
            ('db_query_time', _('Database Query Time')),
            ('security_events', _('Security Events')),
            ('failed_logins', _('Failed Logins')),
            ('api_requests', _('API Requests')),
        ],
        db_index=True,
        help_text=_("Type of metric"),
    )
    
    value = models.FloatField(
        validators=[MinValueValidator(0)],
        help_text=_("Metric value"),
    )
    
    unit = models.CharField(
        max_length=20,
        default='percent',
        help_text=_("Unit of measurement (percent, ms, count, etc.)"),
    )
    
    # Thresholds
    warning_threshold = models.FloatField(
        null=True,
        blank=True,
        help_text=_("Warning threshold value"),
    )
    
    critical_threshold = models.FloatField(
        null=True,
        blank=True,
        help_text=_("Critical threshold value"),
    )
    
    # Status
    status = models.CharField(
        max_length=20,
        choices=[
            ('healthy', _('Healthy')),
            ('warning', _('Warning')),
            ('critical', _('Critical')),
            ('unknown', _('Unknown')),
        ],
        default='healthy',
        db_index=True,
        help_text=_("Current status based on thresholds"),
    )
    
    # Metadata
    metadata = JSONField(
        default=dict,
        blank=True,
        help_text=_("Additional metric metadata"),
    )
    
    # Timestamp
    timestamp = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        help_text=_("Timestamp when metric was recorded"),
    )
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['metric_type', 'timestamp']),
            models.Index(fields=['status', 'timestamp']),
        ]
        verbose_name = _("Health Metric")
        verbose_name_plural = _("Health Metrics")
    
    def __str__(self):
        return f"{self.metric_type}: {self.value} {self.unit} ({self.status})"
    
    def evaluate_status(self):
        """
        Evaluate status based on thresholds.
        
        Returns:
            str: Status (healthy, warning, critical)
        """
        if self.critical_threshold and self.value >= self.critical_threshold:
            return 'critical'
        elif self.warning_threshold and self.value >= self.warning_threshold:
            return 'warning'
        return 'healthy'


class Alert(models.Model):
    """
    Alert model for system and application alerts.
    
    Alerts are generated when metrics exceed thresholds or
    when security events occur.
    """
    
    # Alert Information
    alert_type = models.CharField(
        max_length=50,
        choices=[
            ('system', _('System Alert')),
            ('performance', _('Performance Alert')),
            ('security', _('Security Alert')),
            ('database', _('Database Alert')),
            ('application', _('Application Alert')),
        ],
        db_index=True,
        help_text=_("Type of alert"),
    )
    
    severity = models.CharField(
        max_length=20,
        choices=[
            ('info', _('Info')),
            ('warning', _('Warning')),
            ('critical', _('Critical')),
            ('emergency', _('Emergency')),
        ],
        default='warning',
        db_index=True,
        help_text=_("Alert severity"),
    )
    
    title = models.CharField(
        max_length=200,
        help_text=_("Alert title"),
    )
    
    message = models.TextField(
        help_text=_("Alert message"),
    )
    
    # Source
    source = models.CharField(
        max_length=100,
        help_text=_("Source of the alert (metric, event, etc.)"),
    )
    
    # Status
    status = models.CharField(
        max_length=20,
        choices=[
            ('active', _('Active')),
            ('acknowledged', _('Acknowledged')),
            ('resolved', _('Resolved')),
            ('dismissed', _('Dismissed')),
        ],
        default='active',
        db_index=True,
        help_text=_("Alert status"),
    )
    
    # AI Agent Action
    ai_action_taken = models.BooleanField(
        default=False,
        help_text=_("If True, AI agent has taken action"),
    )
    
    ai_action_description = models.TextField(
        blank=True,
        help_text=_("Description of AI agent action"),
    )
    
    # Metadata
    metadata = JSONField(
        default=dict,
        blank=True,
        help_text=_("Additional alert metadata"),
    )
    
    # Timestamps
    created_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        help_text=_("Timestamp when alert was created"),
    )
    acknowledged_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("Timestamp when alert was acknowledged"),
    )
    resolved_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("Timestamp when alert was resolved"),
    )
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status', 'severity']),
            models.Index(fields=['alert_type', 'created_at']),
        ]
        verbose_name = _("Alert")
        verbose_name_plural = _("Alerts")
    
    def __str__(self):
        return f"{self.severity.upper()}: {self.title}"


class Incident(models.Model):
    """
    Incident model for tracking system incidents.
    
    Incidents are created when critical issues occur and
    require investigation and resolution.
    """
    
    # Incident Information
    title = models.CharField(
        max_length=200,
        help_text=_("Incident title"),
    )
    
    description = models.TextField(
        help_text=_("Incident description"),
    )
    
    incident_type = models.CharField(
        max_length=50,
        choices=[
            ('outage', _('Outage')),
            ('performance', _('Performance Degradation')),
            ('security', _('Security Breach')),
            ('data_loss', _('Data Loss')),
            ('other', _('Other')),
        ],
        db_index=True,
        help_text=_("Type of incident"),
    )
    
    severity = models.CharField(
        max_length=20,
        choices=[
            ('low', _('Low')),
            ('medium', _('Medium')),
            ('high', _('High')),
            ('critical', _('Critical')),
        ],
        default='medium',
        db_index=True,
        help_text=_("Incident severity"),
    )
    
    # Status
    status = models.CharField(
        max_length=20,
        choices=[
            ('open', _('Open')),
            ('investigating', _('Investigating')),
            ('resolved', _('Resolved')),
            ('closed', _('Closed')),
        ],
        default='open',
        db_index=True,
        help_text=_("Incident status"),
    )
    
    # AI Agent Involvement
    ai_detected = models.BooleanField(
        default=False,
        help_text=_("If True, incident was detected by AI agent"),
    )
    
    ai_resolved = models.BooleanField(
        default=False,
        help_text=_("If True, incident was resolved by AI agent"),
    )
    
    ai_actions = JSONField(
        default=list,
        blank=True,
        help_text=_("List of AI agent actions taken"),
    )
    
    # Resolution
    resolution = models.TextField(
        blank=True,
        help_text=_("Incident resolution description"),
    )
    
    # Metadata
    metadata = JSONField(
        default=dict,
        blank=True,
        help_text=_("Additional incident metadata"),
    )
    
    # Timestamps
    created_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        help_text=_("Timestamp when incident was created"),
    )
    resolved_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("Timestamp when incident was resolved"),
    )
    closed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("Timestamp when incident was closed"),
    )
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status', 'severity']),
            models.Index(fields=['incident_type', 'created_at']),
        ]
        verbose_name = _("Incident")
        verbose_name_plural = _("Incidents")
    
    def __str__(self):
        return f"{self.severity.upper()}: {self.title}"


class AIAgentAction(models.Model):
    """
    AI Agent Action model for tracking autonomous actions.
    
    Records all actions taken by the AI agent to maintain
    system health and resolve issues.
    """
    
    # Action Information
    action_type = models.CharField(
        max_length=50,
        choices=[
            ('scale_up', _('Scale Up Resources')),
            ('scale_down', _('Scale Down Resources')),
            ('restart_service', _('Restart Service')),
            ('clear_cache', _('Clear Cache')),
            ('block_ip', _('Block IP Address')),
            ('enable_maintenance', _('Enable Maintenance Mode')),
            ('disable_maintenance', _('Disable Maintenance Mode')),
            ('throttle_requests', _('Throttle Requests')),
            ('increase_timeout', _('Increase Timeout')),
            ('optimize_database', _('Optimize Database')),
            ('other', _('Other')),
        ],
        db_index=True,
        help_text=_("Type of action"),
    )
    
    description = models.TextField(
        help_text=_("Action description"),
    )
    
    # Trigger
    triggered_by = models.CharField(
        max_length=100,
        help_text=_("What triggered this action (alert, metric, etc.)"),
    )
    
    # Status
    status = models.CharField(
        max_length=20,
        choices=[
            ('pending', _('Pending')),
            ('executing', _('Executing')),
            ('completed', _('Completed')),
            ('failed', _('Failed')),
            ('rolled_back', _('Rolled Back')),
        ],
        default='pending',
        db_index=True,
        help_text=_("Action status"),
    )
    
    # Results
    success = models.BooleanField(
        null=True,
        blank=True,
        help_text=_("Whether action was successful"),
    )
    
    result_message = models.TextField(
        blank=True,
        help_text=_("Result message"),
    )
    
    # Metadata
    metadata = JSONField(
        default=dict,
        blank=True,
        help_text=_("Additional action metadata"),
    )
    
    # Timestamps
    created_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        help_text=_("Timestamp when action was created"),
    )
    executed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("Timestamp when action was executed"),
    )
    completed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("Timestamp when action was completed"),
    )
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['action_type', 'status']),
            models.Index(fields=['status', 'created_at']),
        ]
        verbose_name = _("AI Agent Action")
        verbose_name_plural = _("AI Agent Actions")
    
    def __str__(self):
        return f"{self.action_type}: {self.description[:50]}"


class SystemHealth(models.Model):
    """
    Overall system health snapshot.
    
    Provides a snapshot of system health at a point in time.
    """
    
    # Overall Status
    overall_status = models.CharField(
        max_length=20,
        choices=[
            ('healthy', _('Healthy')),
            ('degraded', _('Degraded')),
            ('unhealthy', _('Unhealthy')),
            ('critical', _('Critical')),
        ],
        default='healthy',
        db_index=True,
        help_text=_("Overall system health status"),
    )
    
    # Component Status
    api_status = models.CharField(
        max_length=20,
        choices=[
            ('operational', _('Operational')),
            ('degraded', _('Degraded')),
            ('down', _('Down')),
        ],
        default='operational',
        help_text=_("API status"),
    )
    
    database_status = models.CharField(
        max_length=20,
        choices=[
            ('operational', _('Operational')),
            ('degraded', _('Degraded')),
            ('down', _('Down')),
        ],
        default='operational',
        help_text=_("Database status"),
    )
    
    cache_status = models.CharField(
        max_length=20,
        choices=[
            ('operational', _('Operational')),
            ('degraded', _('Degraded')),
            ('down', _('Down')),
        ],
        default='operational',
        help_text=_("Cache status"),
    )
    
    # Metrics Summary
    cpu_usage = models.FloatField(
        default=0,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        help_text=_("CPU usage percentage"),
    )
    
    memory_usage = models.FloatField(
        default=0,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        help_text=_("Memory usage percentage"),
    )
    
    disk_usage = models.FloatField(
        default=0,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        help_text=_("Disk usage percentage"),
    )
    
    avg_response_time = models.FloatField(
        default=0,
        validators=[MinValueValidator(0)],
        help_text=_("Average response time in milliseconds"),
    )
    
    error_rate = models.FloatField(
        default=0,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        help_text=_("Error rate percentage"),
    )
    
    # Active Alerts
    active_alerts_count = models.PositiveIntegerField(
        default=0,
        help_text=_("Number of active alerts"),
    )
    
    critical_alerts_count = models.PositiveIntegerField(
        default=0,
        help_text=_("Number of critical alerts"),
    )
    
    # Active Incidents
    active_incidents_count = models.PositiveIntegerField(
        default=0,
        help_text=_("Number of active incidents"),
    )
    
    # Metadata
    metadata = JSONField(
        default=dict,
        blank=True,
        help_text=_("Additional health data"),
    )
    
    # Timestamp
    timestamp = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        help_text=_("Timestamp when health snapshot was created"),
    )
    
    class Meta:
        ordering = ['-timestamp']
        get_latest_by = 'timestamp'
        verbose_name = _("System Health")
        verbose_name_plural = _("System Health Snapshots")
    
    def __str__(self):
        return f"System Health: {self.overall_status} at {self.timestamp}"
