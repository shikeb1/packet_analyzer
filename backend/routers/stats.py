def generate_stats(job_id, forwarded, dropped, breakdown):
    total_packets = forwarded + dropped

    return {
        "job_id": job_id,
        "total_packets": total_packets,
        "forwarded": forwarded,
        "dropped": dropped,
        "app_breakdown": breakdown
    }