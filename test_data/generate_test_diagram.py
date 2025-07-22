#!/usr/bin/env python3
"""
Generate a test architectural diagram with various component types.
"""

import cv2
import numpy as np

# Create a blank white image
width, height = 1000, 800
image = np.ones((height, width, 3), dtype=np.uint8) * 255

# Draw components

# 1. Database (circle)
cv2.circle(image, (200, 200), 50, (0, 0, 0), 2)
cv2.putText(image, "Database", (170, 200), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 0), 1)

# 2. API Gateway (wide rectangle)
cv2.rectangle(image, (400, 150), (600, 200), (0, 0, 0), 2)
cv2.putText(image, "API Gateway", (450, 180), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 0), 1)

# 3. Lambda Function (square)
cv2.rectangle(image, (450, 300), (550, 400), (0, 0, 0), 2)
cv2.putText(image, "Lambda", (480, 350), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 0), 1)

# 4. S3 Bucket (rounded rectangle)
cv2.rectangle(image, (700, 150), (800, 250), (0, 0, 0), 2, cv2.LINE_AA)
cv2.putText(image, "S3", (740, 200), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 0), 1)

# 5. Server (tall rectangle)
cv2.rectangle(image, (150, 400), (200, 600), (0, 0, 0), 2)
cv2.putText(image, "Server", (155, 500), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 0), 1)

# 6. Network component (hexagon)
pts = np.array([[700, 400], [750, 380], [800, 400], [800, 450], [750, 470], [700, 450]], np.int32)
pts = pts.reshape((-1, 1, 2))
cv2.polylines(image, [pts], True, (0, 0, 0), 2)
cv2.putText(image, "Network", (730, 430), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 0), 1)

# Draw connections

# 1. Database to API Gateway
cv2.line(image, (250, 200), (400, 175), (0, 0, 0), 2)
cv2.putText(image, "Query", (300, 170), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 0), 1)

# 2. API Gateway to Lambda
cv2.line(image, (500, 200), (500, 300), (0, 0, 0), 2)
cv2.putText(image, "Invoke", (510, 250), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 0), 1)

# 3. Lambda to S3
cv2.line(image, (550, 350), (700, 200), (0, 0, 0), 2)
cv2.putText(image, "Store", (600, 250), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 0), 1)

# 4. Server to Database
cv2.line(image, (200, 400), (200, 250), (0, 0, 0), 2)
cv2.putText(image, "Manage", (150, 325), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 0), 1)

# 5. Lambda to Network
cv2.line(image, (550, 350), (700, 425), (0, 0, 0), 2)
cv2.putText(image, "Connect", (600, 400), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 0), 1)

# Save the image
cv2.imwrite("enhanced/test_diagram.png", image)
print("Test diagram generated: enhanced/test_diagram.png")
