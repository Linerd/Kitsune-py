# Specify the size of training dataset (size = FMgrace + ADgrace)
FMgrace = 5000 #the number of instances taken to learn the feature mapping (the ensemble's architecture)
ADgrace = 50000 #the number of instances used to train the anomaly detector (ensemble itself)

# Specify the size of testing dataset, 0 for infinity
EXECgrace = None

KITSUNE_TRAIN_DATA_KEY = 'kitsune::train'
KITSUNE_TEST_DATA_KEY = 'kitsune::test'
DB_NAME = 'kitsune'

TRAINING_DATA = 'training.pcap'
TESTING_DATA = 'testing.pcap'

RECEIVER_DATA = 'receiver.pcap'

DST_MAC = '08:00:00:00:02:22'
