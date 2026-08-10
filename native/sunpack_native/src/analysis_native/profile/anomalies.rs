fn collect_window_anomalies(
    samples: &[WindowProfile],
    high_threshold: f64,
    low_threshold: f64,
    jump_threshold: f64,
) -> Vec<WindowAnomaly> {
    let mut anomalies = Vec::new();
    for pair in samples.windows(2) {
        let previous = &pair[0];
        let current = &pair[1];
        let delta = current.entropy - previous.entropy;
        if delta.abs() >= jump_threshold {
            anomalies.push(WindowAnomaly {
                anomaly_type: "entropy_jump",
                offset: current.offset,
                previous_offset: Some(previous.offset),
                next_offset: Some(current.offset),
                delta: Some(delta),
                direction: Some(if delta > 0.0 { "up" } else { "down" }),
                dominant_byte: None,
                confidence: confidence_from_delta(delta.abs(), jump_threshold),
                approximate: true,
            });
        }
        if previous.printable_ratio >= 0.55 && current.entropy >= high_threshold {
            anomalies.push(WindowAnomaly {
                anomaly_type: "printable_to_high_entropy",
                offset: current.offset,
                previous_offset: Some(previous.offset),
                next_offset: Some(current.offset),
                delta: None,
                direction: None,
                dominant_byte: None,
                confidence: 0.76,
                approximate: true,
            });
        }
        if previous.entropy >= high_threshold && current.printable_ratio >= 0.50 {
            anomalies.push(WindowAnomaly {
                anomaly_type: "high_entropy_to_printable",
                offset: current.offset,
                previous_offset: Some(previous.offset),
                next_offset: Some(current.offset),
                delta: None,
                direction: None,
                dominant_byte: None,
                confidence: 0.74,
                approximate: true,
            });
        }
        if previous.entropy >= high_threshold
            && (current.zero_ratio >= 0.35 || current.ff_ratio >= 0.35)
        {
            anomalies.push(WindowAnomaly {
                anomaly_type: "high_entropy_to_padding",
                offset: current.offset,
                previous_offset: Some(previous.offset),
                next_offset: Some(current.offset),
                delta: None,
                direction: None,
                dominant_byte: None,
                confidence: 0.80,
                approximate: true,
            });
        }
    }
    if let Some(tail) = samples.last() {
        if tail.zero_ratio >= 0.35 || tail.ff_ratio >= 0.35 {
            anomalies.push(WindowAnomaly {
                anomaly_type: "tail_padding",
                offset: tail.offset,
                previous_offset: None,
                next_offset: None,
                delta: None,
                direction: None,
                dominant_byte: Some(if tail.zero_ratio >= tail.ff_ratio {
                    "zero"
                } else {
                    "ff"
                }),
                confidence: 0.70,
                approximate: true,
            });
        }
        if tail.printable_ratio >= 0.60 && tail.entropy <= low_threshold.max(5.2) {
            anomalies.push(WindowAnomaly {
                anomaly_type: "tail_printable_region",
                offset: tail.offset,
                previous_offset: None,
                next_offset: None,
                delta: None,
                direction: None,
                dominant_byte: None,
                confidence: 0.62,
                approximate: true,
            });
        }
    }
    anomalies
}
