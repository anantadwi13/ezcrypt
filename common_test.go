package ezcrypt

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"io"
	"testing"
)

func TestSetRandomReader(t *testing.T) {
	type args struct {
		reader io.Reader
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "success",
			args:    args{reader: rand.Reader},
			wantErr: false,
		},
		{
			name:    "error nil",
			args:    args{reader: nil},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := SetRandomReader(tt.args.reader)
			if (err != nil) != tt.wantErr {
				t.Errorf("SetRandomReader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			assert.Equal(t, tt.args.reader, getRandomReader())
		})
	}
}

func TestSetBase64Encoder(t *testing.T) {
	type args struct {
		encoder *base64.Encoding
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "success",
			args:    args{encoder: base64.StdEncoding},
			wantErr: false,
		},
		{
			name:    "error nil",
			args:    args{encoder: nil},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := SetBase64Encoder(tt.args.encoder)
			if (err != nil) != tt.wantErr {
				t.Errorf("SetBase64Encoder() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			assert.Equal(t, tt.args.encoder, getBase64Encoder())
		})
	}
}

var lipsum = []byte(`
Lorem ipsum dolor sit amet, consectetur adipiscing elit. Praesent eget tincidunt mi. Aenean fermentum erat eget euismod efficitur. Aenean nec venenatis turpis. Fusce finibus nunc dui, at dapibus mauris fringilla eget. Curabitur eget lacinia dolor, sed viverra dolor. Orci varius natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Pellentesque tristique nibh id bibendum faucibus. Morbi nibh nunc, consequat ut dignissim in, ornare vel justo. In nec commodo metus. Nulla ut orci lorem. Mauris ut libero bibendum, ullamcorper dui eget, placerat lacus. Nullam eu consectetur elit. Nullam vulputate ornare dui at dictum. Donec a ligula at purus fringilla cursus feugiat vitae enim. Quisque venenatis magna leo, nec iaculis ante porta vitae.

Vestibulum gravida enim sem, a dignissim erat maximus non. Pellentesque porttitor pharetra tortor a vulputate. In hac habitasse platea dictumst. Praesent commodo nunc vitae leo ullamcorper, a ornare felis laoreet. Ut ornare pellentesque dolor eu bibendum. Cras porttitor scelerisque sodales. Curabitur nisl massa, scelerisque sit amet mauris et, ultrices suscipit dui. Aliquam id erat consectetur, lobortis dolor ut, varius dolor. Proin vitae imperdiet leo. Quisque et tempus tellus, eget pulvinar velit. Nullam eu erat sem.

Sed ut lectus interdum, lacinia nibh ac, convallis lorem. Nulla massa ex, sollicitudin id felis in, consequat consequat nunc. Curabitur vel venenatis dolor. Nunc ullamcorper efficitur orci vel tempus. In pulvinar quam sed odio venenatis convallis quis ut ante. Quisque dapibus justo bibendum, fringilla felis cursus, sodales ipsum. Ut pulvinar nunc semper enim porttitor, a iaculis purus pulvinar. Aliquam et mi justo. Integer quis vehicula massa. Donec dapibus pretium magna, in bibendum odio lacinia eu. Morbi blandit eleifend tortor, eget porttitor urna. Aliquam varius ac odio vel rhoncus.

Aliquam laoreet sapien felis, vitae fermentum nunc eleifend ac. Maecenas eu facilisis felis, sit amet dignissim lectus. Vestibulum sagittis ipsum ante, id tincidunt arcu vulputate et. Sed odio eros, luctus a sem eget, mattis eleifend massa. Praesent pellentesque pharetra turpis a gravida. Nulla facilisi. Quisque at nulla sit amet erat suscipit pulvinar ac ullamcorper massa. Quisque nec purus finibus, feugiat felis at, egestas nibh. Proin ut tincidunt risus. Quisque ut enim ante. Duis maximus justo et enim tempor rhoncus. Nam ut nibh pharetra, consequat est sit amet, convallis lacus. Nam non leo elementum, aliquet risus in, efficitur dolor. Cras finibus lectus ac sollicitudin porta.

Curabitur volutpat vehicula nunc, a tristique lectus ornare nec. Vestibulum commodo auctor imperdiet. Suspendisse mattis elementum tortor at consectetur. Aenean egestas maximus felis, sed pharetra eros. Proin eget tempor mi. Nulla fermentum diam id fermentum pulvinar. Mauris maximus libero in tellus pellentesque convallis. Curabitur placerat, odio non commodo tincidunt, lacus nisi scelerisque lacus, at sollicitudin nunc ligula ut neque.
`)
