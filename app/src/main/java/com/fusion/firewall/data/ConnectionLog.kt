package com.fusion.firewall.data

import com.fusion.firewall.ai.ThreatAssessment
import com.fusion.firewall.data.model.ConnectionEvent
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.concurrent.ConcurrentLinkedDeque

/**
 * Process-wide realtime bus. The VPN service publishes observed connection
 * attempts here; the UI collects them for the live dashboard. Kept intentionally
 * lightweight (a bounded ring buffer) so it can be written to from the packet
 * loop without allocation pressure.
 */
object ConnectionLog {

    private const val MAX_EVENTS = 500

    private val buffer = ConcurrentLinkedDeque<ConnectionEvent>()

    private val _events = MutableStateFlow<List<ConnectionEvent>>(emptyList())
    val events: StateFlow<List<ConnectionEvent>> = _events.asStateFlow()

    /** Hot stream of the single latest event, for prompts and AI scoring. */
    private val _latest = MutableSharedFlow<ConnectionEvent>(extraBufferCapacity = 64)
    val latest: SharedFlow<ConnectionEvent> = _latest.asSharedFlow()

    private val _blockedCount = MutableStateFlow(0L)
    val blockedCount: StateFlow<Long> = _blockedCount.asStateFlow()

    private val _allowedCount = MutableStateFlow(0L)
    val allowedCount: StateFlow<Long> = _allowedCount.asStateFlow()

    /** AI verdicts keyed by ConnectionEvent.id, filled by auto- and manual assessment. */
    private val _verdicts = MutableStateFlow<Map<String, ThreatAssessment>>(emptyMap())
    val verdicts: StateFlow<Map<String, ThreatAssessment>> = _verdicts.asStateFlow()

    fun recordAssessment(eventId: String, assessment: ThreatAssessment) {
        _verdicts.value = _verdicts.value + (eventId to assessment)
    }

    fun record(event: ConnectionEvent) {
        buffer.addFirst(event)
        while (buffer.size > MAX_EVENTS) buffer.pollLast()
        _events.value = buffer.toList()
        _latest.tryEmit(event)
        if (event.allowed) _allowedCount.value++ else _blockedCount.value++
    }

    fun clear() {
        buffer.clear()
        _events.value = emptyList()
        _blockedCount.value = 0
        _allowedCount.value = 0
        _verdicts.value = emptyMap()
    }
}
