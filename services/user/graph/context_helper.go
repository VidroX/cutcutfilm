package graph

import (
	"context"
	"log"
	"os"
	"strings"

	"github.com/VidroX/cutcutfilm-shared/translator"
	"github.com/VidroX/cutcutfilm/services/user/core/environment"
)

func GetLocalizer(ctx context.Context) *translator.NebulaLocalizer {
	contextTranslator := ctx.Value(translator.Key).(*translator.NebulaLocalizer)

	if contextTranslator == nil {
		if strings.EqualFold(os.Getenv(environment.KeysDebug), "True") {
			log.Println("Could not retrieve translator")
		}

		return nil
	}

	return contextTranslator
}
