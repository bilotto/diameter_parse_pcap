from diameter_telecom import DiameterMessage, Subscriber

class DiameterMessages:
    def __init__(self):
        self.messages = []

    def add_message(self, message: DiameterMessage):
        self.messages.append(message)

    def get_messages(self):
        # return self.messages
        # Return sorted by timestamp
        return sorted(self.messages, key=lambda x: x.timestamp if x.timestamp else float('inf'))

