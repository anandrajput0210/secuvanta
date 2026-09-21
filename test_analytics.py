from core.history import get_history
from core.analytics import calculate_analytics


# Load scan history
history = get_history()


# Calculate analytics
analytics = calculate_analytics(history)


# Display result
print("\nSECUVANTA ANALYTICS TEST")
print("=" * 40)

for key, value in analytics.items():

    print(f"{key}: {value}")