import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
class DeepANN(nn.Module):
    def __init__(self, input_size, output_size, lr=0.01):
        super(DeepANN, self).__init__()
        self.fc1 = nn.Linear(input_size, 128)
        self.fc2 = nn.Linear(128, 256)
        self.fc3 = nn.Linear(256, 128)
        self.fc4 = nn.Linear(128, output_size)  # Output layer
        self.relu = nn.ReLU()
        self.dropout = nn.Dropout(0.3)  # Dropout to prevent overfitting

        # Loss function & optimizer
        self.criterion = nn.CrossEntropyLoss()
        self.optimizer = optim.Adam(self.parameters(), lr=lr)

    def forward(self, x):
        x = self.relu(self.fc1(x))
        x = self.relu(self.fc2(x))
        x = self.dropout(self.relu(self.fc3(x)))
        x = self.fc4(x)  # No activation (CrossEntropyLoss expects raw logits)
        return x

    def fit(self, X_train, y_train, epochs=10):
        """Trains the model."""
        for epoch in range(epochs):
            self.optimizer.zero_grad()
            outputs = self(X_train)
            loss = self.criterion(outputs, y_train)
            loss.backward()
            self.optimizer.step()
            print(f"Epoch [{epoch+1}/{epochs}], Loss: {loss.item():.4f}")

    def predict(self, X):
        x = torch.tensor(np.array(X, dtype=float), dtype=torch.float32)
        """Returns predicted class labels (0 or 1)."""
        with torch.no_grad():
            logits = self(x)
            predictions = torch.argmax(logits, axis=1)  # Convert logits to class labels
        return predictions.numpy()

    def predict_proba(self, X):
        x = torch.tensor(np.array(X, dtype=float), dtype=torch.float32)
        """Returns predicted probabilities for each class."""
        with torch.no_grad():
            logits = self(x)
            probabilities = torch.softmax(logits, axis=1)  # Apply softmax for probabilities
        return probabilities.numpy()